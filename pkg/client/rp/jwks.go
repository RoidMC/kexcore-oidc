// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package rp

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/v1/pkg/client"
	"github.com/roidmc/kexcore-oidc/v1/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/v1/pkg/oidc"
)

func NewRemoteKeySet(httpClient *http.Client, jwksURL string, opts ...func(*remoteKeySet)) oidc.KeySet {
	keyset := &remoteKeySet{httpClient: httpClient, jwksURL: jwksURL}
	for _, opt := range opts {
		opt(keyset)
	}
	return keyset
}

// SkipRemoteCheck will suppress checking for new remote keys if signature validation fails with cached keys
// and no kid header is set in the JWT.
//
// This might be handy to save some unnecessary round trips in cases where the JWT does not contain a kid header and
// there is only a single remote key.
// Please notice that remote keys will then only be fetched if cached keys are empty.
func SkipRemoteCheck() func(set *remoteKeySet) {
	return func(set *remoteKeySet) {
		set.skipRemoteCheck = true
	}
}

type remoteKeySet struct {
	jwksURL         string
	httpClient      *http.Client
	defaultAlg      string
	skipRemoteCheck bool

	// guard all other fields
	mu sync.Mutex

	// inflight suppresses parallel execution of updateKeys and allows
	// multiple goroutines to wait for its result.
	inflight *inflight

	// A set of cached keys.
	cachedKeys jwk.Set
}

// inflight is used to wait on some in-flight request from multiple goroutines.
type inflight struct {
	doneCh chan struct{}

	keys jwk.Set
	err  error
}

func newInflight() *inflight {
	return &inflight{doneCh: make(chan struct{})}
}

// wait returns a channel that multiple goroutines can receive on. Once it returns
// a value, the inflight request is done and result() can be inspected.
func (i *inflight) wait() <-chan struct{} {
	return i.doneCh
}

// done can only be called by a single goroutine. It records the result of the
// inflight request and signals other goroutines that the result is safe to
// inspect.
func (i *inflight) done(keys jwk.Set, err error) {
	i.keys = keys
	i.err = err
	close(i.doneCh)
}

// result cannot be called until the wait() channel has returned a value.
func (i *inflight) result() (jwk.Set, error) {
	return i.keys, i.err
}

func (r *remoteKeySet) VerifySignature(ctx context.Context, rawToken []byte) ([]byte, error) {
	ctx, span := client.Tracer.Start(ctx, "VerifySignature")
	defer span.End()

	jwsMsg, err := jws.Parse(rawToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: error parsing JWS: %w", err)
	}

	keyID, alg := oidc.GetKeyIDAndAlg(jwsMsg)
	if alg == "" {
		alg = r.defaultAlg
	}
	payload, err := r.verifySignatureCached(rawToken, jwsMsg, keyID, alg)
	if payload != nil {
		return payload, nil
	}
	if err != nil {
		return nil, err
	}
	return r.verifySignatureRemote(ctx, rawToken, jwsMsg, keyID, alg)
}

// verifySignatureCached checks for a matching key in the cached key set.
//
// if there is only one possible, it tries to verify the signature and will return the payload if successful
//
// it only returns an error if signature validation fails and keys exactMatch which is if either:
// - both kid are empty and skipRemoteCheck is set to true
// - or both (JWT and JWK) kid are equal
//
// otherwise it will return no error (so remote keys will be loaded)
func (r *remoteKeySet) verifySignatureCached(rawToken []byte, jwsMsg *jws.Message, keyID, alg string) ([]byte, error) {
	keys := r.keysFromCache()
	if keys == nil || keys.Len() == 0 {
		return nil, nil
	}

	// Convert jwk.Set to []jwk.Key
	var jwkKeys []jwk.Key
	for _, key := range keys.All() {
		jwkKeys = append(jwkKeys, key)
	}

	key, err := oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, jwkKeys...)
	if err != nil {
		// no key / multiple found, try with remote keys
		return nil, nil //nolint:nilerr
	}

	sig := jwsMsg.Signatures()[0]
	sigAlg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return nil, nil
	}

	// SM2 signatures use custom verification since jwx does not support SM2.
	if crypto.IsSM2Algorithm(alg) {
		payload, err := verifySM2Signature(jwsMsg, key)
		if err != nil {
			jwkKid, _ := key.KeyID()
			if !r.exactMatch(jwkKid, keyID) {
				return nil, nil
			}
			return nil, fmt.Errorf("SM2 signature verification failed: %w", err)
		}
		return payload, nil
	}

	payload, err := jws.Verify(rawToken, jws.WithKey(sigAlg, key))
	if payload != nil {
		return payload, nil
	}

	jwkKid, _ := key.KeyID()
	if !r.exactMatch(jwkKid, keyID) {
		// no exact key match, try getting better match with remote keys
		return nil, nil
	}
	return nil, fmt.Errorf("signature verification failed: %w", err)
}

func (r *remoteKeySet) exactMatch(jwkID, jwsID string) bool {
	if jwkID == "" && jwsID == "" {
		return r.skipRemoteCheck
	}
	return jwkID == jwsID
}

func (r *remoteKeySet) verifySignatureRemote(ctx context.Context, rawToken []byte, jwsMsg *jws.Message, keyID, alg string) ([]byte, error) {
	ctx, span := client.Tracer.Start(ctx, "verifySignatureRemote")
	defer span.End()

	keys, err := r.keysFromRemote(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch key for signature validation: %w", err)
	}

	// Convert jwk.Set to []jwk.Key
	var jwkKeys []jwk.Key
	for _, key := range keys.All() {
		jwkKeys = append(jwkKeys, key)
	}

	key, err := oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, jwkKeys...)
	if err != nil {
		return nil, fmt.Errorf("unable to validate signature: %w", err)
	}

	sig := jwsMsg.Signatures()[0]
	sigAlg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return nil, fmt.Errorf("missing algorithm in token header")
	}

	// SM2 signatures use custom verification since jwx does not support SM2.
	if crypto.IsSM2Algorithm(alg) {
		return verifySM2Signature(jwsMsg, key)
	}

	payload, err := jws.Verify(rawToken, jws.WithKey(sigAlg, key))
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	return payload, nil
}

func (r *remoteKeySet) keysFromCache() jwk.Set {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cachedKeys
}

// keysFromRemote syncs the key set from the remote set, records the values in the
// cache, and returns the key set.
func (r *remoteKeySet) keysFromRemote(ctx context.Context) (jwk.Set, error) {
	ctx, span := client.Tracer.Start(ctx, "keysFromRemote")
	defer span.End()

	// Need to lock to inspect the inflight request field.
	r.mu.Lock()
	// If there's not a current inflight request, create one.
	if r.inflight == nil {
		r.inflight = newInflight()

		// This goroutine has exclusive ownership over the current inflight
		// request. It releases the resource by nil'ing the inflight field
		// once the goroutine is done.
		go r.updateKeys(ctx)
	}
	inflight := r.inflight
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-inflight.wait():
		return inflight.result()
	}
}

func (r *remoteKeySet) updateKeys(ctx context.Context) {
	ctx, span := client.Tracer.Start(ctx, "updateKeys")
	defer span.End()

	// Sync keys and finish inflight when that's done.
	keys, err := r.fetchRemoteKeys(ctx)

	r.inflight.done(keys, err)

	// Lock to update the keys and indicate that there is no longer an
	// inflight request.
	r.mu.Lock()
	defer r.mu.Unlock()

	if err == nil {
		r.cachedKeys = keys
	}

	// Free inflight so a different request can run.
	r.inflight = nil
}

func (r *remoteKeySet) fetchRemoteKeys(ctx context.Context) (jwk.Set, error) {
	ctx, span := client.Tracer.Start(ctx, "fetchRemoteKeys")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, "GET", r.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: can't create request: %v", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to get keys: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to read response: %v", err)
	}

	keyset, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to parse keys: %v", err)
	}
	return keyset, nil
}

// verifySM2Signature verifies an SM2 JWS signature using SM3 hash.
func verifySM2Signature(jwsMsg *jws.Message, key jwk.Key) ([]byte, error) {
	sig := jwsMsg.Signatures()[0]
	sigBytes, err := base64.RawURLEncoding.DecodeString(string(sig.Signature()))
	if err != nil {
		return nil, fmt.Errorf("error decoding SM2 signature: %w", err)
	}

	signingInput, err := crypto.BuildSM2SigningInput(sig.ProtectedHeaders(), jwsMsg.Payload())
	if err != nil {
		return nil, err
	}

	// Extract the ECDSA public key from the JWK
	raw, err := jwk.Export[any](key)
	if err != nil {
		return nil, fmt.Errorf("error extracting public key: %w", err)
	}
	pubKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PublicKey, got %T", raw)
	}

	if err := crypto.VerifySM2JWSSignature(signingInput, sigBytes, pubKey); err != nil {
		return nil, err
	}
	return jwsMsg.Payload(), nil
}
