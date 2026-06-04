// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"

	gm "github.com/roidmc/kexcore-oidc/pkg/crypto/gm"
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

	if !gm.SM2Verify(pubKey, digest, signature) {
		return fmt.Errorf("SM2 signature verification failed")
	}
	return nil
}

// BuildSM2SigningInput reconstructs the JWS signing input from the
// protected header and payload of a JWS message.
// Returns base64url(header) + "." + base64url(payload).
// protectedHeaders can be any value that json.Marshal can handle (e.g. jws.Headers).
//
// Deprecated: Use BuildSigningInput instead. This function is kept for backward compatibility.
func BuildSM2SigningInput(protectedHeaders any, payload []byte) ([]byte, error) {
	return BuildSigningInput(protectedHeaders, payload)
}

// BuildSigningInput reconstructs the JWS signing input from the
// protected header and payload of a JWS message.
// Returns base64url(header) + "." + base64url(payload).
// protectedHeaders can be any value that json.Marshal can handle (e.g. jws.Headers).
func BuildSigningInput(protectedHeaders any, payload []byte) ([]byte, error) {
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

// --- SM9 JWK support ---

// SM9SignJWK represents a JSON Web Key for an SM9 signing master public key.
// SM9 uses identity-based cryptography (IBC) where the master public key is used
// for verification and user signing keys are derived from the master key + uid.
// The kid field serves as the identity identifier.
type SM9SignJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Hid int    `json:"hid"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

// NewSM9SignJWK constructs an SM9SignJWK from an SM9 signing master public key.
// The hid parameter is the SM9 private key generation function identifier
// (1 for signing, 3 for encryption).
func NewSM9SignJWK(masterPubKey *sm9.SignMasterPublicKey, kid, use string, hid int) (SM9SignJWK, error) {
	raw := masterPubKey.Bytes()
	// SignMasterPublicKey.Bytes() returns uncompressed point: 04 || x(64 bytes) || y(64 bytes)
	// Total length should be 129 bytes (1 + 64 + 64).
	if len(raw) != 129 || raw[0] != 4 {
		return SM9SignJWK{}, fmt.Errorf("invalid SM9 master public key format: expected 129 bytes uncompressed point, got %d bytes", len(raw))
	}
	xBytes := raw[1:65]
	yBytes := raw[65:129]

	return SM9SignJWK{
		Kty: "EC",
		Crv: "SM9",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		Hid: hid,
		Alg: SGD_SM3_SM9,
		Kid: kid,
		Use: use,
	}, nil
}

// ParseSM9SignMasterPublicKey parses an SM9 signing master public key from
// JWK x and y fields.
func ParseSM9SignMasterPublicKey(xBase64, yBase64 string) (*sm9.SignMasterPublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(xBase64)
	if err != nil {
		return nil, fmt.Errorf("error decoding SM9 master public key x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yBase64)
	if err != nil {
		return nil, fmt.Errorf("error decoding SM9 master public key y: %w", err)
	}
	// Reconstruct uncompressed point: 04 || x || y
	raw := make([]byte, 1+len(xBytes)+len(yBytes))
	raw[0] = 4
	copy(raw[1:], xBytes)
	copy(raw[1+len(xBytes):], yBytes)
	return sm9.UnmarshalSignMasterPublicKeyRaw(raw)
}

// VerifySM9JWSSignature verifies an SM9 JWS signature using SM3 hash.
// SM9 verification requires the master public key and the user identifier (uid).
// The uid must be extracted from the JWS protected header (custom "uid" parameter).
//
// Parameters:
//   - signingInput: the JWS signing input (base64url(header) + "." + base64url(payload))
//   - signature: the raw signature bytes from the JWS
//   - masterPubKey: the SM9 signing master public key
//   - uid: the user identifier used to derive the signing key
func VerifySM9JWSSignature(signingInput []byte, signature []byte, masterPubKey *sm9.SignMasterPublicKey, uid []byte) error {
	h, err := GetHashAlgorithm(SGD_SM3_SM9)
	if err != nil {
		return fmt.Errorf("error getting SM3 hash: %w", err)
	}
	h.Write(signingInput)
	digest := h.Sum(nil)

	if !gm.SM9Verify(masterPubKey, uid, digest, signature) {
		return fmt.Errorf("SM9 signature verification failed")
	}
	return nil
}

// IsSM9Algorithm returns true if the given algorithm identifier is
// an SM9 signing algorithm (SGD_SM3_SM9).
func IsSM9Algorithm(alg string) bool {
	return alg == SGD_SM3_SM9
}

// --- JWKS parsing support ---

// JWKSKey represents a parsed key from a JWKS endpoint.
// The Key field is one of: *ecdsa.PublicKey (SM2), *sm9.SignMasterPublicKey (SM9).
// Standard keys (RSA, ECDSA, EdDSA) are NOT handled here — use jwx for those.
type JWKSKey struct {
	Kid string
	Alg string
	Use string
	Key any
}

type rawJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Hid int    `json:"hid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

type rawJWKS struct {
	Keys []rawJWK `json:"keys"`
}

// ParseJWKSBytes parses JWKS JSON and returns keys with GM/T algorithms
// (SGD_SM3_SM2, SGD_SM3_SM9). Standard algorithm keys are skipped —
// use jwx for those.
func ParseJWKSBytes(data []byte) ([]JWKSKey, error) {
	var ks rawJWKS
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, fmt.Errorf("error parsing JWKS: %w", err)
	}

	var keys []JWKSKey
	for _, raw := range ks.Keys {
		switch {
		case IsSM2Algorithm(raw.Alg):
			pubKey, err := parseSM2PublicKey(raw)
			if err != nil {
				continue
			}
			keys = append(keys, JWKSKey{Kid: raw.Kid, Alg: raw.Alg, Use: raw.Use, Key: pubKey})

		case IsSM9Algorithm(raw.Alg):
			masterPubKey, err := ParseSM9SignMasterPublicKey(raw.X, raw.Y)
			if err != nil {
				continue
			}
			keys = append(keys, JWKSKey{Kid: raw.Kid, Alg: raw.Alg, Use: raw.Use, Key: masterPubKey})
		}
	}
	return keys, nil
}

// FindJWKSKey finds a key by kid and algorithm from a parsed JWKS key list.
func FindJWKSKey(keys []JWKSKey, kid, alg string) *JWKSKey {
	for i := range keys {
		if keys[i].Alg == alg && (kid == "" || keys[i].Kid == kid) {
			return &keys[i]
		}
	}
	return nil
}

// SM2PublicKeyFromJWK parses an SM2 public key from JWK fields.
func SM2PublicKeyFromJWK(crv, xBase64, yBase64 string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "SM2-P-256", "sm2p256v1":
		curve = sm2.P256()
	default:
		return nil, fmt.Errorf("unsupported SM2 curve: %s", crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xBase64)
	if err != nil {
		return nil, fmt.Errorf("error decoding x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yBase64)
	if err != nil {
		return nil, fmt.Errorf("error decoding y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("SM2 public key point is not on curve")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func parseSM2PublicKey(raw rawJWK) (*ecdsa.PublicKey, error) {
	return SM2PublicKeyFromJWK(raw.Crv, raw.X, raw.Y)
}
