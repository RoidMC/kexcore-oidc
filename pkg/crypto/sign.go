// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	gmsm "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// Signer encapsulates key material and algorithm for JWS signing operations.
type Signer struct {
	algorithm string
	key       interface{}
	keyID     string
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

// Algorithm returns the JWA signature algorithm string.
func (s *Signer) Algorithm() string {
	return s.algorithm
}

// Sign signs the payload and returns the compact serialized JWS.
func (s *Signer) Sign(payload []byte) (string, error) {
	if s.sm2Priv != nil {
		return s.signSM2(payload)
	}
	if s.sm9Priv != nil {
		return s.signSM9(payload)
	}

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

func (s *Signer) signSM2(payload []byte) (string, error) {
	h, err := GetHashAlgorithm(s.algorithm)
	if err != nil {
		return "", err
	}
	h.Write(payload)
	digest := h.Sum(nil)

	signature, err := s.sm2Priv.Sign(rand.Reader, digest, nil)
	if err != nil {
		return "", err
	}

	headerJSON, err := json.Marshal(map[string]interface{}{
		"alg": s.algorithm,
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return encodedHeader + "." + encodedPayload + "." + encodedSignature, nil
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
func (s *Signer) signSM9(payload []byte) (string, error) {
	if len(s.sm9UID) == 0 {
		return "", errors.New("signer: SM9 signing requires uid to be set via SetSM9UID")
	}

	h, err := GetHashAlgorithm(s.algorithm)
	if err != nil {
		return "", err
	}
	h.Write(payload)
	digest := h.Sum(nil)

	signature, err := SM9Sign(s.sm9Priv, digest)
	if err != nil {
		return "", err
	}

	headerMap := map[string]interface{}{
		"alg": s.algorithm,
		"typ": "JWT",
		"uid": base64.RawURLEncoding.EncodeToString(s.sm9UID),
	}
	if s.keyID != "" {
		headerMap["kid"] = s.keyID
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
