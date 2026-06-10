// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	gmsm "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	gm "github.com/roidmc/kexcore-oidc/pkg/crypto/gm"
)

// SignJWS signs the payload using the given JWK and returns compact JWS serialization.
// The JWK must contain a private key and have an "alg" header set.
//
// This is the recommended entry point for JWS signing. It delegates to Signer,
// which checks the ProviderRegistry first for HSM/KMS overrides, then falls
// back to the built-in software implementation (gmsm for GM/T, jwx for
// international algorithms).
func SignJWS(payload []byte, key jwk.Key) (string, error) {
	algStr, ok := key.Algorithm()
	if !ok || algStr.String() == "" {
		return "", fmt.Errorf("crypto: JWK has no algorithm set")
	}

	kid, _ := key.KeyID()
	signer, err := NewSigner(algStr.String(), key, kid)
	if err != nil {
		return "", fmt.Errorf("crypto: failed to create signer: %w", err)
	}
	return signer.Sign(payload)
}

// Signer encapsulates key material and algorithm for JWS signing operations.
type Signer struct {
	algorithm string
	key       interface{}
	keyID     string
	tokenType string
	sm2Priv   *gmsm.PrivateKey
	sm9Priv   *sm9.SignPrivateKey
	sm9UID    []byte
}

// NewSigner creates a Signer for the given algorithm and key.
// The algorithm must be a valid JWA signature algorithm string (e.g. "RS256", "ES384", "EdDSA", "SGD_SM3_SM2").
//
// For SM9 signing (SGD_SM3_SM9), key must be a *sm9.SignPrivateKey and
// the Signer must be configured with the user identifier (uid) via
// [Signer.SetSM9UID] before signing.
func NewSigner(algorithm string, key interface{}, keyID string) (*Signer, error) {
	s := &Signer{
		algorithm: algorithm,
		key:       key,
		keyID:     keyID,
	}

	if isSM2SignAlgorithm(algorithm) {
		sm2Key, ok := key.(*gmsm.PrivateKey)
		if !ok {
			return nil, errors.New("signer: SM2 algorithm requires *sm2.PrivateKey")
		}
		s.sm2Priv = sm2Key
		return s, nil
	}

	if isSM9SignAlgorithm(algorithm) {
		sm9Key, ok := key.(*sm9.SignPrivateKey)
		if !ok {
			return nil, errors.New("signer: SM9 algorithm requires *sm9.SignPrivateKey")
		}
		s.sm9Priv = sm9Key
		return s, nil
	}

	if _, ok := jwa.LookupSignatureAlgorithm(algorithm); !ok {
		return nil, fmt.Errorf("signer: unsupported algorithm %q", algorithm)
	}

	return s, nil
}

// SetSM9UID sets the user identifier (uid) for SM9 signing.
// This must be called before Sign when using SGD_SM3_SM9 algorithm.
func (s *Signer) SetSM9UID(uid []byte) {
	s.sm9UID = uid
}

// SetTokenType sets the JWT typ header value (e.g. "JWT", "logout+jwt").
// If empty, the default "JWT" is used.
func (s *Signer) SetTokenType(tokenType string) {
	s.tokenType = tokenType
}

// Algorithm returns the JWA signature algorithm string.
func (s *Signer) Algorithm() string {
	return s.algorithm
}

// Sign signs the payload and returns the compact serialized JWS.
// Sign signs the payload and returns the compact serialized JWS.
// It checks the ProviderRegistry first for HSM/KMS overrides (any algorithm),
// then falls back to the built-in software implementation (gmsm for GM/T,
// jwx for international algorithms).
func (s *Signer) Sign(payload []byte) (string, error) {
	// DefaultRegistry contains built-in software providers for all supported algorithms.
	// HSM/KMS vendors can override any algorithm by registering their own provider
	// in init() (last registration wins).
	if provider, ok := DefaultRegistry.GetSigner(s.algorithm); ok {
		key := s.key
		if s.sm9Priv != nil && len(s.sm9UID) > 0 {
			key = &SM9SignKey{PrivateKey: s.sm9Priv, UID: s.sm9UID}
		}
		return provider.Sign(context.Background(), s.keyID, s.tokenTypeOrDefault(), key, payload)
	}

	// Fallback for international algorithms not registered in DefaultRegistry.
	alg, _ := jwa.LookupSignatureAlgorithm(s.algorithm)
	headers := jws.NewHeaders()
	_ = headers.Set(jws.AlgorithmKey, alg)

	if s.keyID != "" {
		_ = headers.Set(jws.KeyIDKey, s.keyID)
	}

	signed, err := jws.Sign(payload, jws.WithKey(alg, s.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

func (s *Signer) tokenTypeOrDefault() string {
	if s.tokenType != "" {
		return s.tokenType
	}
	return "JWT"
}

func signSM2(algorithm, keyID, tokenType string, priv *gmsm.PrivateKey, payload []byte) (string, error) {
	h, err := GetHashAlgorithm(algorithm)
	if err != nil {
		return "", err
	}
	h.Write(payload)
	digest := h.Sum(nil)

	signature, err := priv.Sign(rand.Reader, digest, nil)
	if err != nil {
		return "", err
	}

	headerJSON, err := json.Marshal(map[string]interface{}{
		"alg": algorithm,
		"typ": tokenType,
	})
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return encodedHeader + "." + encodedPayload + "." + encodedSignature, nil
}

func (s *Signer) signSM2(payload []byte) (string, error) {
	return signSM2(s.algorithm, s.keyID, s.tokenTypeOrDefault(), s.sm2Priv, payload)
}

// Sign marshals payload to JSON and signs it.
func Sign(payload interface{}, signer *Signer) (string, error) {
	marshalled, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return SignPayload(marshalled, signer)
}

// SignPayload signs raw payload bytes.
func SignPayload(payload []byte, signer *Signer) (string, error) {
	if signer == nil {
		return "", errors.New("missing signer")
	}
	return signer.Sign(payload)
}

// isSM2SignAlgorithm returns true if the algorithm identifier is the
// GM/T 0125.1 SGD_SM3_SM2 digital signature algorithm.
func isSM2SignAlgorithm(alg string) bool {
	return alg == SGD_SM3_SM2
}

// isSM9SignAlgorithm returns true if the algorithm identifier is the
// GM/T 0125.1 SGD_SM3_SM9 digital signature algorithm.
func isSM9SignAlgorithm(alg string) bool {
	return alg == SGD_SM3_SM9
}

// signSM9 signs the payload using SM9 identity-based signature.
// The JWS protected header includes the uid parameter per GM/T 0125.1.
func signSM9(algorithm, keyID, tokenType string, priv *sm9.SignPrivateKey, uid []byte, payload []byte) (string, error) {
	if len(uid) == 0 {
		return "", errors.New("signer: SM9 signing requires uid")
	}

	h, err := GetHashAlgorithm(algorithm)
	if err != nil {
		return "", err
	}
	h.Write(payload)
	digest := h.Sum(nil)

	signature, err := gm.SM9Sign(priv, digest)
	if err != nil {
		return "", err
	}

	headerMap := map[string]interface{}{
		"alg": algorithm,
		"typ": tokenType,
		"uid": base64.RawURLEncoding.EncodeToString(uid),
	}
	if keyID != "" {
		headerMap["kid"] = keyID
	}

	headerJSON, err := json.Marshal(headerMap)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return encodedHeader + "." + encodedPayload + "." + encodedSignature, nil
}

func (s *Signer) signSM9(payload []byte) (string, error) {
	return signSM9(s.algorithm, s.keyID, s.tokenTypeOrDefault(), s.sm9Priv, s.sm9UID, payload)
}
