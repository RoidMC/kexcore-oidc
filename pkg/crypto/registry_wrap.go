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
)

// ---------------------------------------------------------------------------
// Primitive-level interfaces — implement these to extend the SDK without
// touching JWS/JWE formatting. The SDK handles hashing, header construction,
// base64 encoding, CEK generation, and content encryption/decryption.
//
// Usage:
//
//	type myHSM struct{}
//
//	func (h *myHSM) Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error) {
//	    return hsmClient.Sign(ctx, keyID, digest)
//	}
//
//	// Register — SDK handles hashing + JWS compact assembly
//	crypto.DefaultRegistry.RegisterSigner(crypto.SGD_SM3_SM2,
//	    crypto.WrapSignPrimitive(crypto.SGD_SM3_SM2, &myHSM{}))
// ---------------------------------------------------------------------------

// SignPrimitive is the minimal signing interface. Implement this when your
// HSM/KMS provides Sign(digest) -> signature and you want the SDK to handle
// hashing, JWS header construction, and compact serialization.
type SignPrimitive interface {
	// Sign signs the pre-computed digest and returns the raw signature bytes.
	// The SDK has already applied the correct hash algorithm for the given keyID.
	Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error)
}

// VerifyPrimitive is the minimal verification interface.
type VerifyPrimitive interface {
	// Verify verifies the signature against the signing input (header.payload bytes).
	// key is the public key material (type depends on algorithm).
	Verify(ctx context.Context, signingInput, signature []byte, key interface{}) error
}

// WrapSignPrimitive wraps a SignPrimitive into a SignProvider.
// The SDK computes the hash digest and assembles the JWS compact serialization;
// the primitive only performs the raw cryptographic signing operation.
func WrapSignPrimitive(alg string, p SignPrimitive) SignProvider {
	return &wrappedSignProvider{alg: alg, p: p}
}

// WrapVerifyPrimitive wraps a VerifyPrimitive into a VerifyProvider.
func WrapVerifyPrimitive(alg string, p VerifyPrimitive) VerifyProvider {
	return &wrappedVerifyProvider{alg: alg, p: p}
}

// wrappedSignProvider implements SignProvider by delegating the raw signing
// to a SignPrimitive and handling JWS formatting in Sign().
type wrappedSignProvider struct {
	alg string
	p   SignPrimitive
}

func (w *wrappedSignProvider) Algorithm() string { return w.alg }

func (w *wrappedSignProvider) Sign(ctx context.Context, keyID, tokenType string, key interface{}, payload []byte) (string, error) {
	h, err := GetHashAlgorithm(w.alg)
	if err != nil {
		return "", err
	}
	h.Write(payload)
	digest := h.Sum(nil)

	signature, err := w.p.Sign(ctx, keyID, digest)
	if err != nil {
		return "", fmt.Errorf("sign primitive: %w", err)
	}

	return BuildJWSCompact(w.alg, keyID, tokenType, payload, signature, nil)
}

// wrappedVerifyProvider implements VerifyProvider by delegating to a VerifyPrimitive.
type wrappedVerifyProvider struct {
	alg string
	p   VerifyPrimitive
}

func (w *wrappedVerifyProvider) Algorithm() string { return w.alg }

func (w *wrappedVerifyProvider) Verify(ctx context.Context, signingInput, signature []byte, key interface{}) error {
	return w.p.Verify(ctx, signingInput, signature, key)
}

// ---------------------------------------------------------------------------
// JWE key-wrapping primitives — implement these to extend JWE without
// touching CEK generation, content encryption, or JWE compact assembly.
//
// Usage:
//
//	type myHSMKeyWrap struct{}
//
//	func (h *myHSMKeyWrap) WrapKey(ctx context.Context, key interface{}, keySize int) (cek, wrappedKey []byte, err error) {
//	    return hsmClient.Wrap(ctx, key, keySize)
//	}
//
//	crypto.DefaultRegistry.RegisterJWEEncryptor(crypto.SGD_SM2_3,
//	    crypto.WrapKeyWrapPrimitive(crypto.SGD_SM2_3, crypto.SGD_SM4_GCM, &myHSMKeyWrap{}))
// ---------------------------------------------------------------------------

// KeyWrapPrimitive is the minimal JWE key-wrapping interface. Implement this
// when your HSM/KMS provides key wrapping and you want the SDK to handle
// CEK generation, content encryption, and JWE compact assembly.
//
// WrapKey takes the wrapping key and desired CEK size, generates (or obtains)
// a content encryption key, wraps it with the wrapping key, and returns both.
type KeyWrapPrimitive interface {
	// WrapKey wraps a CEK of the given size with the provided key.
	// Returns the raw CEK and the wrapped key bytes.
	WrapKey(ctx context.Context, key interface{}, keySize int) (cek, wrappedKey []byte, err error)
}

// KeyUnwrapPrimitive is the minimal JWE key-unwrapping interface.
type KeyUnwrapPrimitive interface {
	// UnwrapKey unwraps the wrapped key bytes and returns the raw CEK.
	UnwrapKey(ctx context.Context, key interface{}, wrappedKey []byte, keySize int) (cek []byte, err error)
}

// WrapKeyWrapPrimitive wraps a KeyWrapPrimitive into a JWEEncryptProvider.
// The SDK generates the IV, encrypts the content with the CEK, and assembles
// the JWE compact serialization; the primitive only wraps the key.
func WrapKeyWrapPrimitive(alg, enc string, p KeyWrapPrimitive) JWEEncryptProvider {
	return &wrappedJWEEncryptProvider{alg: alg, enc: enc, p: p}
}

// WrapKeyUnwrapPrimitive wraps a KeyUnwrapPrimitive into a JWEDecryptProvider.
func WrapKeyUnwrapPrimitive(alg string, p KeyUnwrapPrimitive) JWEDecryptProvider {
	return &wrappedJWEDecryptProvider{alg: alg, p: p}
}

// wrappedJWEEncryptProvider implements JWEEncryptProvider by delegating key
// wrapping to a KeyWrapPrimitive and handling JWE framing in Encrypt().
type wrappedJWEEncryptProvider struct {
	alg string
	enc string
	p   KeyWrapPrimitive
}

func (w *wrappedJWEEncryptProvider) KeyAlgorithm() string      { return w.alg }
func (w *wrappedJWEEncryptProvider) ContentEncryption() string { return w.enc }

func (w *wrappedJWEEncryptProvider) Encrypt(ctx context.Context, plaintext []byte, key interface{}) (string, error) {
	keySize := contentKeySize(w.enc)
	nonceSize := contentNonceSize(w.enc)

	cek, wrappedKey, err := w.p.WrapKey(ctx, key, keySize)
	if err != nil {
		return "", fmt.Errorf("key wrap primitive: %w", err)
	}

	iv := make([]byte, nonceSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	// Content encryption goes through the ContentEncryptor registry, so HSM can
	// also override the symmetric encryption layer independently.
	sealed, err := DispatchContentEncrypt(w.enc, cek, iv, plaintext, nil)
	if err != nil {
		return "", fmt.Errorf("content encrypt: %w", err)
	}

	return BuildJWECompact(w.alg, w.enc, wrappedKey, iv, sealed)
}

// wrappedJWEDecryptProvider implements JWEDecryptProvider by delegating key
// unwrapping to a KeyUnwrapPrimitive.
type wrappedJWEDecryptProvider struct {
	alg string
	p   KeyUnwrapPrimitive
}

func (w *wrappedJWEDecryptProvider) KeyAlgorithm() string { return w.alg }

func (w *wrappedJWEDecryptProvider) Decrypt(ctx context.Context, compact string, key interface{}) ([]byte, error) {
	parts, header, err := ParseJWECompact(compact)
	if err != nil {
		return nil, err
	}
	if header.Algorithm != w.alg {
		return nil, fmt.Errorf("%w: expected alg=%s, got %s", ErrJWEHeaderMismatch, w.alg, header.Algorithm)
	}

	wrappedKey, err := decodeBase64(parts[1], "encrypted key")
	if err != nil {
		return nil, err
	}

	cek, err := w.p.UnwrapKey(ctx, key, wrappedKey, contentKeySize(header.Encryption))
	if err != nil {
		return nil, fmt.Errorf("key unwrap primitive: %w", err)
	}

	iv, err := decodeBase64(parts[2], "IV")
	if err != nil {
		return nil, err
	}
	ciphertext, err := decodeBase64(parts[3], "ciphertext")
	if err != nil {
		return nil, err
	}
	tag, err := decodeBase64(parts[4], "tag")
	if err != nil {
		return nil, err
	}
	sealed := append(ciphertext, tag...)
	aad := []byte(parts[0])

	return DispatchContentDecrypt(header.Encryption, cek, iv, sealed, aad)
}

// ---------------------------------------------------------------------------
// JWE compact assembly helper — exported so that KeyWrapPrimitive wrappers
// and external implementations can build JWE without duplicating formatting.
// ---------------------------------------------------------------------------

// BuildJWECompact assembles a JWE compact serialization from raw components.
// This is the single place where JWE formatting happens; both the built-in
// JWE providers and external wrappers use it.
//
// The sealed parameter is ciphertext||tag (combined output from content encryption).
func BuildJWECompact(alg, enc string, encryptedKey, iv, sealed []byte) (string, error) {
	const tagSize = 16
	if len(sealed) < tagSize {
		return "", errors.New("crypto: sealed data too short (need at least tag bytes)")
	}
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	header := map[string]string{"alg": alg, "enc": enc}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("crypto: failed to marshal JWE header: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(encryptedKey) + "." +
		base64.RawURLEncoding.EncodeToString(iv) + "." +
		base64.RawURLEncoding.EncodeToString(ciphertext) + "." +
		base64.RawURLEncoding.EncodeToString(tag), nil
}

// decodeBase64 is a small helper to avoid repeating base64 decode + error wrapping.
func decodeBase64(s, label string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %s: %w", label, err)
	}
	return b, nil
}

// contentKeySize returns the CEK size in bytes for the given JWE content encryption algorithm.
func contentKeySize(enc string) int {
	switch enc {
	case "A128GCM", "A128CBC-HS256":
		return 16
	case "A192GCM", "A192CBC-HS384":
		return 24
	case "A256GCM", "A256CBC-HS512":
		return 32
	case SGD_SM4_GCM, SGD_SM4_CCM:
		return 16
	default:
		return 16
	}
}

// contentNonceSize returns the IV/nonce size in bytes for the given JWE content encryption algorithm.
func contentNonceSize(enc string) int {
	switch enc {
	case "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512":
		return 16 // AES block size
	default:
		return 12 // GCM/CCM nonce
	}
}
