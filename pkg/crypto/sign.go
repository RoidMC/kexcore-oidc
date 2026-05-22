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
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// Signer encapsulates key material and algorithm for JWS signing operations.
type Signer struct {
	algorithm string
	key       interface{}
	keyID     string
	sm2Priv   *gmsm.PrivateKey
}

// NewSigner creates a Signer for the given algorithm and key.
// The algorithm must be a valid JWA signature algorithm string (e.g. "RS256", "ES384", "EdDSA", "SM2").
func NewSigner(algorithm string, key interface{}, keyID string) (*Signer, error) {
	s := &Signer{
		algorithm: algorithm,
		key:       key,
		keyID:     keyID,
	}

	if algorithm == SM2 {
		sm2Key, ok := key.(*gmsm.PrivateKey)
		if !ok {
			return nil, errors.New("signer: SM2 algorithm requires *sm2.PrivateKey")
		}
		s.sm2Priv = sm2Key
		return s, nil
	}

	if _, ok := jwa.LookupSignatureAlgorithm(algorithm); !ok {
		return nil, fmt.Errorf("signer: unsupported algorithm %q", algorithm)
	}

	return s, nil
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
	h, err := GetHashAlgorithm(SM2)
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
		"alg": SM2,
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