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

	"github.com/emmansun/gmsm/sm9"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/pkg/client"
	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

func NewRemoteKeySet(httpClient *http.Client, jwksURL string, opts ...func(*remoteKeySet)) protocol.KeySet {
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
	// GM/T keys (SM2, SM9) parsed from JWKS that jwx cannot handle.
	cachedGMKeys []crypto.JWKSKey
}

// inflight is used to wait on some in-flight request from multiple goroutines.
type inflight struct {
	doneCh chan struct{}

	keys   jwk.Set
	gmKeys []crypto.JWKSKey
	err    error
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
func (i *inflight) done(keys jwk.Set, gmKeys []crypto.JWKSKey, err error) {
	i.keys = keys
	i.gmKeys = gmKeys
	i.err = err
	close(i.doneCh)
}

// result cannot be called until the wait() channel has returned a value.
func (i *inflight) result() (jwk.Set, []crypto.JWKSKey, error) {
	return i.keys, i.gmKeys, i.err
}

func (r *remoteKeySet) VerifySignature(ctx context.Context, rawToken []byte) ([]byte, error) {
	ctx, span := client.Tracer.Start(ctx, "VerifySignature")
	defer span.End()

	jwsMsg, err := jws.Parse(rawToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: error parsing JWS: %w", err)
	}

	keyID, alg := protocol.GetKeyIDAndAlg(jwsMsg)
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
	gmKeys := r.gmKeysFromCache()

	if (keys == nil || keys.Len() == 0) && len(gmKeys) == 0 {
		return nil, nil
	}

	// SM2/SM9: use custom JWKS parser
	if crypto.IsSM2Algorithm(alg) || crypto.IsSM9Algorithm(alg) {
		if len(gmKeys) == 0 {
			return nil, nil
		}
		gmKey := crypto.FindJWKSKey(gmKeys, keyID, alg)
		if gmKey == nil {
			return nil, nil
		}
		payload, err := verifyGMSignature(jwsMsg, gmKey)
		if err != nil {
			if keyID != "" && gmKey.Kid != keyID {
				return nil, nil
			}
			return nil, fmt.Errorf("%s signature verification failed: %w", alg, err)
		}
		return payload, nil
	}

	// Standard keys: use jwx
	if keys == nil || keys.Len() == 0 {
		return nil, nil
	}

	var jwkKeys []jwk.Key
	for _, key := range keys.All() {
		jwkKeys = append(jwkKeys, key)
	}

	key, err := protocol.FindMatchingKey(keyID, protocol.KeyUseSignature, alg, jwkKeys...)
	if err != nil {
		return nil, nil
	}

	sig := jwsMsg.Signatures()[0]
	sigAlg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return nil, nil
	}

	payload, err := jws.Verify(rawToken, jws.WithKey(sigAlg, key))
	if payload != nil {
		return payload, nil
	}

	jwkKid, _ := key.KeyID()
	if !r.exactMatch(jwkKid, keyID) {
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

	keys, gmKeys, err := r.keysFromRemote(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch key for signature validation: %w", err)
	}

	// SM2/SM9: use custom JWKS parser
	if crypto.IsSM2Algorithm(alg) || crypto.IsSM9Algorithm(alg) {
		gmKey := crypto.FindJWKSKey(gmKeys, keyID, alg)
		if gmKey == nil {
			return nil, fmt.Errorf("no matching %s key found for kid=%q", alg, keyID)
		}
		return verifyGMSignature(jwsMsg, gmKey)
	}

	// Standard keys: use jwx
	var jwkKeys []jwk.Key
	for _, key := range keys.All() {
		jwkKeys = append(jwkKeys, key)
	}

	key, err := protocol.FindMatchingKey(keyID, protocol.KeyUseSignature, alg, jwkKeys...)
	if err != nil {
		return nil, fmt.Errorf("unable to validate signature: %w", err)
	}

	sig := jwsMsg.Signatures()[0]
	sigAlg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return nil, fmt.Errorf("missing algorithm in token header")
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

func (r *remoteKeySet) gmKeysFromCache() []crypto.JWKSKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cachedGMKeys
}

// keysFromRemote syncs the key set from the remote set, records the values in the
// cache, and returns the key set.
func (r *remoteKeySet) keysFromRemote(ctx context.Context) (jwk.Set, []crypto.JWKSKey, error) {
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
		return nil, nil, ctx.Err()
	case <-inflight.wait():
		keys, gmKeys, err := inflight.result()
		return keys, gmKeys, err
	}
}

func (r *remoteKeySet) updateKeys(ctx context.Context) {
	ctx, span := client.Tracer.Start(ctx, "updateKeys")
	defer span.End()

	// Sync keys and finish inflight when that's done.
	keys, gmKeys, err := r.fetchRemoteKeys(ctx)

	// Lock to update cached keys, notify waiters, and free inflight atomically.
	// This prevents a race where a new goroutine enters keysFromRemote between
	// inflight.done() and inflight = nil, causing a duplicate fetch.
	r.mu.Lock()
	if err == nil {
		r.cachedKeys = keys
		r.cachedGMKeys = gmKeys
	}
	r.inflight.done(keys, gmKeys, err)
	r.inflight = nil
	r.mu.Unlock()
}

func (r *remoteKeySet) fetchRemoteKeys(ctx context.Context) (jwk.Set, []crypto.JWKSKey, error) {
	ctx, span := client.Tracer.Start(ctx, "fetchRemoteKeys")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, "GET", r.jwksURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc: can't create request: %v", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc: failed to get keys: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc: failed to read response: %v", err)
	}

	keyset, err := jwk.Parse(body)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc: failed to parse keys: %v", err)
	}

	// Parse GM/T keys (SM2, SM9) that jwx cannot handle.
	gmKeys, _ := crypto.ParseJWKSBytes(body)

	return keyset, gmKeys, nil
}

// verifyGMSignature verifies an SM2 or SM9 JWS signature.
func verifyGMSignature(jwsMsg *jws.Message, gmKey *crypto.JWKSKey) ([]byte, error) {
	sig := jwsMsg.Signatures()[0]
	sigBytes, err := base64.RawURLEncoding.DecodeString(string(sig.Signature()))
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %w", err)
	}

	signingInput, err := crypto.BuildSigningInput(sig.ProtectedHeaders(), jwsMsg.Payload())
	if err != nil {
		return nil, err
	}

	switch {
	case crypto.IsSM2Algorithm(gmKey.Alg):
		pubKey, ok := gmKey.Key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected *ecdsa.PublicKey for SM2, got %T", gmKey.Key)
		}
		if err := crypto.VerifySM2JWSSignature(signingInput, sigBytes, pubKey); err != nil {
			return nil, err
		}

	case crypto.IsSM9Algorithm(gmKey.Alg):
		masterPubKey, ok := gmKey.Key.(*sm9.SignMasterPublicKey)
		if !ok {
			return nil, fmt.Errorf("expected *sm9.SignMasterPublicKey for SM9, got %T", gmKey.Key)
		}
		uidVal, ok := sig.ProtectedHeaders().Field("uid")
		if !ok {
			return nil, fmt.Errorf("SM9 signature missing required 'uid' header parameter")
		}
		uid, ok := uidVal.(string)
		if !ok {
			return nil, fmt.Errorf("SM9 'uid' header parameter must be a string, got %T", uidVal)
		}
		if err := crypto.VerifySM9JWSSignature(signingInput, sigBytes, masterPubKey, []byte(uid)); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported GM algorithm: %s", gmKey.Alg)
	}

	return jwsMsg.Payload(), nil
}
