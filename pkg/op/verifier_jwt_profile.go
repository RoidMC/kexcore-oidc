// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm9"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// JWTProfileVerifier extends oidc.Verifier with
// a jwtProfileKeyStorage and a function to check
// the subject in a token.
type JWTProfileVerifier struct {
	oidc.Verifier
	Storage      JWTProfileKeyStorage
	keySet       oidc.KeySet
	CheckSubject func(request *oidc.JWTTokenRequest) error
}

// NewJWTProfileVerifier creates an oidc.Verifier for JWT Profile assertions (authorization grant and client authentication)
func NewJWTProfileVerifier(storage JWTProfileKeyStorage, issuer string, maxAgeIAT, offset time.Duration, opts ...JWTProfileVerifierOption) *JWTProfileVerifier {
	return newJWTProfileVerifier(storage, nil, issuer, maxAgeIAT, offset, opts...)
}

// NewJWTProfileVerifierKeySet creates an oidc.Verifier for JWT Profile assertions (authorization grant and client authentication)
func NewJWTProfileVerifierKeySet(keySet oidc.KeySet, issuer string, maxAgeIAT, offset time.Duration, opts ...JWTProfileVerifierOption) *JWTProfileVerifier {
	return newJWTProfileVerifier(nil, keySet, issuer, maxAgeIAT, offset, opts...)
}

func newJWTProfileVerifier(storage JWTProfileKeyStorage, keySet oidc.KeySet, issuer string, maxAgeIAT, offset time.Duration, opts ...JWTProfileVerifierOption) *JWTProfileVerifier {
	j := &JWTProfileVerifier{
		Verifier: oidc.Verifier{
			Issuer:    issuer,
			MaxAgeIAT: maxAgeIAT,
			Offset:    offset,
		},
		Storage:      storage,
		keySet:       keySet,
		CheckSubject: SubjectIsIssuer,
	}

	for _, opt := range opts {
		opt(j)
	}

	return j
}

type JWTProfileVerifierOption func(*JWTProfileVerifier)

// SubjectCheck sets a custom function to check the subject.
// Defaults to SubjectIsIssuer()
func SubjectCheck(check func(request *oidc.JWTTokenRequest) error) JWTProfileVerifierOption {
	return func(verifier *JWTProfileVerifier) {
		verifier.CheckSubject = check
	}
}

// VerifyJWTAssertion verifies the assertion string from JWT Profile (authorization grant and client authentication)
//
// checks audience, exp, iat, signature and that issuer and sub are the same
func VerifyJWTAssertion(ctx context.Context, assertion string, v *JWTProfileVerifier) (*oidc.JWTTokenRequest, error) {
	ctx, span := Tracer.Start(ctx, "VerifyJWTAssertion")
	defer span.End()

	request := new(oidc.JWTTokenRequest)
	payload, err := oidc.ParseToken(assertion, request)
	if err != nil {
		return nil, mapVerifierError(err)
	}

	if err = oidc.CheckAudience(request, v.Issuer); err != nil {
		return nil, mapVerifierError(err)
	}

	if err = oidc.CheckExpiration(request, v.Offset); err != nil {
		return nil, mapVerifierError(err)
	}

	if err = oidc.CheckIssuedAt(request, v.MaxAgeIAT, v.Offset); err != nil {
		return nil, mapVerifierError(err)
	}

	if err = v.CheckSubject(request); err != nil {
		return nil, err
	}

	keySet := v.keySet
	if keySet == nil {
		keySet = &jwtProfileKeySet{storage: v.Storage, clientID: request.Issuer}
	}
	if err = oidc.CheckSignature(ctx, assertion, payload, request, nil, keySet); err != nil {
		return nil, mapVerifierError(err)
	}
	return request, nil
}

func mapVerifierError(err error) error {
	pairs := []struct {
		oidcSentinel, protocolSentinel error
	}{
		{oidc.ErrParse, protocol.ErrParse},
		{oidc.ErrAudience, protocol.ErrAudience},
		{oidc.ErrExpired, protocol.ErrExpired},
		{oidc.ErrIatInFuture, protocol.ErrIatInFuture},
		{oidc.ErrIatMissing, protocol.ErrIatMissing},
		{oidc.ErrIatToOld, protocol.ErrIatToOld},
		{oidc.ErrSubjectInvalid, protocol.ErrSubjectInvalid},
		{oidc.ErrIssuerInvalid, protocol.ErrIssuerInvalid},
		{oidc.ErrSignatureMissing, protocol.ErrSignatureMissing},
		{oidc.ErrSignatureMultiple, protocol.ErrSignatureMultiple},
		{oidc.ErrSignatureUnsupportedAlg, protocol.ErrSignatureUnsupportedAlg},
		{oidc.ErrSignatureInvalidPayload, protocol.ErrSignatureInvalidPayload},
		{oidc.ErrSignatureInvalid, protocol.ErrSignatureInvalid},
		{oidc.ErrAuthTimeNotPresent, protocol.ErrAuthTimeNotPresent},
		{oidc.ErrAuthTimeToOld, protocol.ErrAuthTimeToOld},
		{oidc.ErrAcrInvalid, protocol.ErrAcrInvalid},
	}
	for _, p := range pairs {
		if !errors.Is(err, p.oidcSentinel) {
			continue
		}
		suffix := strings.TrimPrefix(err.Error(), p.oidcSentinel.Error())
		var innerErr error
		if mu, ok := err.(interface{ Unwrap() []error }); ok {
			for _, w := range mu.Unwrap() {
				if w != p.oidcSentinel {
					innerErr = w
					break
				}
			}
		}
		if innerErr != nil {
			return fmt.Errorf("%w (%w)", p.protocolSentinel, innerErr)
		}
		if suffix == "" {
			return p.protocolSentinel
		}
		return fmt.Errorf("%w%s", p.protocolSentinel, suffix)
	}
	return err
}

// JWTProfileKeyStorage interface for fetching keys by ID and client ID
type JWTProfileKeyStorage interface {
	GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (jwk.Key, error)
}

// SM9JWTProfileKeyStorage extends JWTProfileKeyStorage to support SM9 identity-based
// signatures where the verification key is a master public key + uid rather than a jwk.Key.
type SM9JWTProfileKeyStorage interface {
	JWTProfileKeyStorage
	GetSM9MasterPublicKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*sm9.SignMasterPublicKey, error)
}

// SubjectIsIssuer checks that subject equals issuer
func SubjectIsIssuer(request *oidc.JWTTokenRequest) error {
	if request.Issuer != request.Subject {
		return protocol.ErrSubjectInvalid
	}
	return nil
}

type jwtProfileKeySet struct {
	storage  JWTProfileKeyStorage
	clientID string
}

// VerifySignature implements oidc.KeySet by getting the public key from Storage implementation
func (k *jwtProfileKeySet) VerifySignature(ctx context.Context, rawToken []byte) (payload []byte, err error) {
	ctx, span := Tracer.Start(ctx, "VerifySignature")
	defer span.End()

	jwsMsg, err := jws.Parse(rawToken)
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	keyID, _ := oidc.GetKeyIDAndAlg(jwsMsg)
	key, err := k.storage.GetKeyByIDAndClientID(ctx, keyID, k.clientID)
	if err != nil {
		return nil, fmt.Errorf("error fetching keys: %w", err)
	}

	// Verify using jwx
	sig := jwsMsg.Signatures()[0]
	sigAlg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return nil, fmt.Errorf("error fetching keys: missing algorithm in token header")
	}

	// SM2 signatures use custom verification since jwx does not support SM2.
	if crypto.IsSM2Algorithm(sigAlg.String()) {
		return verifySM2SignatureFromKey(jwsMsg, key)
	}

	// SM9 signatures use custom verification since jwx does not support SM9.
	if crypto.IsSM9Algorithm(sigAlg.String()) {
		return k.verifySM9Signature(ctx, jwsMsg, rawToken, keyID)
	}

	payload, err = jws.Verify(rawToken, jws.WithKey(sigAlg, key))
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// verifySM2SignatureFromKey verifies an SM2 JWS signature using a jwk.Key.
func verifySM2SignatureFromKey(jwsMsg *jws.Message, key jwk.Key) ([]byte, error) {
	sig := jwsMsg.Signatures()[0]
	sigBytes, err := base64.RawURLEncoding.DecodeString(string(sig.Signature()))
	if err != nil {
		return nil, fmt.Errorf("error decoding SM2 signature: %w", err)
	}

	signingInput, err := crypto.BuildSigningInput(sig.ProtectedHeaders(), jwsMsg.Payload())
	if err != nil {
		return nil, err
	}

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

// verifySM9Signature verifies an SM9 JWS signature using the master public key from storage.
func (k *jwtProfileKeySet) verifySM9Signature(ctx context.Context, jwsMsg *jws.Message, rawToken []byte, keyID string) ([]byte, error) {
	sm9Storage, ok := k.storage.(SM9JWTProfileKeyStorage)
	if !ok {
		return nil, fmt.Errorf("SM9 JWT Profile verification requires SM9JWTProfileKeyStorage")
	}

	masterPubKey, err := sm9Storage.GetSM9MasterPublicKeyByIDAndClientID(ctx, keyID, k.clientID)
	if err != nil {
		return nil, fmt.Errorf("error fetching SM9 master public key: %w", err)
	}

	sig := jwsMsg.Signatures()[0]
	sigBytes, err := base64.RawURLEncoding.DecodeString(string(sig.Signature()))
	if err != nil {
		return nil, fmt.Errorf("error decoding SM9 signature: %w", err)
	}

	// Extract uid from JWS protected header
	uidVal, ok := sig.ProtectedHeaders().Field("uid")
	if !ok {
		return nil, fmt.Errorf("SM9 signature missing uid in protected header")
	}
	uidB64, ok := uidVal.(string)
	if !ok {
		return nil, fmt.Errorf("SM9 uid header parameter must be a string, got %T", uidVal)
	}
	uid, err := base64.RawURLEncoding.DecodeString(uidB64)
	if err != nil {
		return nil, fmt.Errorf("error decoding SM9 uid: %w", err)
	}

	signingInput, err := crypto.BuildSigningInput(sig.ProtectedHeaders(), jwsMsg.Payload())
	if err != nil {
		return nil, err
	}

	if err := crypto.VerifySM9JWSSignature(signingInput, sigBytes, masterPubKey, uid); err != nil {
		return nil, err
	}
	return jwsMsg.Payload(), nil
}
