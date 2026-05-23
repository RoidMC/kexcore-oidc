// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// SM2JWK represents a JSON Web Key for an SM2 public key per GM/T 0125.4-2022.
// SM2 keys use kty "EC" with crv "SM2-P-256" and standard x/y coordinates.
// This type exists because the jwx library does not recognize the SM2 curve
// or the SGD_SM3_SM2 algorithm, so we cannot use jwk.Import or jwk.ParseKey.
type SM2JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

// NewSM2JWK constructs an SM2JWK from an SM2 public key.
// Coordinates are encoded as base64url per RFC 7518 §6.2.1.2.
func NewSM2JWK(pubKey *ecdsa.PublicKey, kid, use string) SM2JWK {
	byteLen := (pubKey.Curve.Params().BitSize + 7) / 8
	xBytes := pubKey.X.FillBytes(make([]byte, byteLen))
	yBytes := pubKey.Y.FillBytes(make([]byte, byteLen))

	return SM2JWK{
		Kty: "EC",
		Crv: "SM2-P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		Alg: SGD_SM3_SM2,
		Kid: kid,
		Use: use,
	}
}

// VerifySM2JWSSignature verifies an SM2 JWS signature using SM3 hash.
// This function handles the full verification flow: decode the signature,
// reconstruct the signing input, hash with SM3, and verify with SM2.
//
// Parameters:
//   - signingInput: the JWS signing input (base64url(header) + "." + base64url(payload))
//   - signature: the raw signature bytes from the JWS
//   - pubKey: the SM2 public key for verification
func VerifySM2JWSSignature(signingInput []byte, signature []byte, pubKey *ecdsa.PublicKey) error {
	h, err := GetHashAlgorithm(SGD_SM3_SM2)
	if err != nil {
		return fmt.Errorf("error getting SM3 hash: %w", err)
	}
	h.Write(signingInput)
	digest := h.Sum(nil)

	if !SM2Verify(pubKey, digest, signature) {
		return fmt.Errorf("SM2 signature verification failed")
	}
	return nil
}

// BuildSM2SigningInput reconstructs the JWS signing input from the
// protected header and payload of a JWS message.
// Returns base64url(header) + "." + base64url(payload).
// protectedHeaders can be any value that json.Marshal can handle (e.g. jws.Headers).
func BuildSM2SigningInput(protectedHeaders any, payload []byte) ([]byte, error) {
	headerJSON, err := json.Marshal(protectedHeaders)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JWS header: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	return []byte(encodedHeader + "." + encodedPayload), nil
}

// IsSM2Algorithm returns true if the given algorithm identifier is
// an SM2 signing algorithm (SGD_SM3_SM2 or SM2-SM3 alias).
func IsSM2Algorithm(alg string) bool {
	return alg == SGD_SM3_SM2 || alg == "SM2-SM3"
}
