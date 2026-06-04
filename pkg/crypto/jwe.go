// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"

	gm "github.com/roidmc/kexcore-oidc/pkg/crypto/gm"
)

var (
	ErrInvalidJWECompact = errors.New("kexcore/crypto: invalid JWE compact serialization")
	ErrInvalidJWEParts   = errors.New("kexcore/crypto: JWE compact serialization must have exactly 5 parts")
	ErrJWEKeyDecrypt     = errors.New("kexcore/crypto: failed to decrypt JWE encrypted key")
	ErrJWEContentDecrypt = errors.New("kexcore/crypto: failed to decrypt JWE content")
	ErrJWEHeaderMismatch = errors.New("kexcore/crypto: JWE header algorithm mismatch")
	ErrJWEUnsupportedEnc = errors.New("kexcore/crypto: unsupported JWE content encryption algorithm")
)

const (
	// SM4GCMTagSize is the GCM authentication tag size for SM4 (128 bits).
	SM4GCMTagSize = 16
	// SM4CCMTagSize is the CCM authentication tag size for SM4 (128 bits).
	SM4CCMTagSize = 16
)

// jweHeader represents the JOSE header for JWE per GM/T 0125.3.
type jweHeader struct {
	Algorithm   string `json:"alg"`
	Encryption  string `json:"enc"`
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
}

// --- SM2 + SM4-GCM JWE ---

// SM2EncryptJWE encrypts plaintext using the GM/T 0125.3 JWE specification
// with SM2 key wrapping (SGD_SM2_3) and SM4-GCM content encryption (SGD_SM4_GCM).
//
// Encryption flow:
//  1. Generate a random 128-bit Content Encryption Key (CEK).
//  2. Wrap the CEK using SM2 public key encryption (SGD_SM2_3, ASN.1 encoding).
//  3. Generate a random 96-bit IV for SM4-GCM.
//  4. Encrypt plaintext using SM4-GCM with the CEK, using the base64url-encoded
//     protected header as additional authenticated data (AAD).
//
// Returns the JWE compact serialization:
//
//	base64url(protected_header) . base64url(encrypted_key) . base64url(iv) . base64url(ciphertext) . base64url(tag)
func SM2EncryptJWE(publicKey *ecdsa.PublicKey, plaintext []byte) (string, error) {
	// 1. Generate random CEK (128 bits for SM4)
	cek := make([]byte, gm.SM4BlockSize)
	if _, err := rand.Read(cek); err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to generate CEK: %w", err)
	}

	// 2. Generate random IV (96 bits for GCM)
	iv := make([]byte, gm.SM4GCMNonceSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to generate IV: %w", err)
	}

	// 3. Build and encode JWE protected header
	header := jweHeader{
		Algorithm:  SGD_SM2_3,
		Encryption: SGD_SM4_GCM,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to marshal JWE header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// 4. Wrap CEK with SM2 public key (SGD_SM2_3, ASN.1 encoding per GB/T 35276)
	encryptedKey, err := gm.SM2EncryptASN1(publicKey, cek)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to wrap CEK with SM2: %w", err)
	}
	encryptedKeyB64 := base64.RawURLEncoding.EncodeToString(encryptedKey)

	// 5. Encrypt plaintext with SM4-GCM using AAD = headerB64
	aad := []byte(headerB64)
	sealed, err := gm.SM4EncryptGCMWithNonce(cek, iv, plaintext, aad)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to encrypt with SM4-GCM: %w", err)
	}

	// 6. Split ciphertext and authentication tag
	// GCM output: ciphertext || tag (tag = SM4GCMTagSize bytes)
	if len(sealed) < SM4GCMTagSize {
		return "", errors.New("kexcore/crypto: SM4-GCM output too short")
	}
	ciphertext := sealed[:len(sealed)-SM4GCMTagSize]
	tag := sealed[len(sealed)-SM4GCMTagSize:]

	// 7. Build JWE compact serialization
	ivB64 := base64.RawURLEncoding.EncodeToString(iv)
	ciphertextB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	tagB64 := base64.RawURLEncoding.EncodeToString(tag)

	return headerB64 + "." + encryptedKeyB64 + "." + ivB64 + "." + ciphertextB64 + "." + tagB64, nil
}

// SM2DecryptJWE decrypts a GM/T 0125.3 JWE compact serialization
// with SM2 key wrapping (SGD_SM2_3) and SM4-GCM content encryption (SGD_SM4_GCM).
//
// Decryption flow:
//  1. Parse the JWE compact serialization into its 5 components.
//  2. Verify the JWE protected header uses SGD_SM2_3 + SGD_SM4_GCM.
//  3. Decrypt the encrypted key using the SM2 private key to recover the CEK.
//  4. Decrypt the ciphertext using SM4-GCM with the recovered CEK, using the
//     base64url-encoded protected header as AAD.
func SM2DecryptJWE(privateKey *sm2.PrivateKey, compact string) ([]byte, error) {
	parts, header, err := ParseJWECompact(compact)
	if err != nil {
		return nil, err
	}

	if header.Algorithm != SGD_SM2_3 {
		return nil, fmt.Errorf("%w: expected alg=%s, got %s", ErrJWEHeaderMismatch, SGD_SM2_3, header.Algorithm)
	}

	// Decode encrypted key
	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode encrypted key: %w", ErrInvalidJWECompact, err)
	}

	// Unwrap CEK with SM2 private key
	cek, err := gm.SM2Decrypt(privateKey, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWEKeyDecrypt, err)
	}

	return decryptJWEContent(cek, header.Encryption, parts)
}

// --- SM9 + SM4-CCM/GCM JWE ---

// SM9EncryptJWE encrypts plaintext using the GM/T 0125.3 JWE specification
// with SM9 key wrapping (SGD_SM9_3) and SM4 content encryption.
//
// The enc parameter specifies the content encryption algorithm:
//   - SGD_SM4_GCM: SM4 in GCM mode (default)
//   - SGD_SM4_CCM: SM4 in CCM mode
func SM9EncryptJWE(masterPubKey *sm9.EncryptMasterPublicKey, uid []byte, enc string, plaintext []byte) (string, error) {
	// 1. Wrap a new CEK with SM9 (SGD_SM9_3)
	// SM9 WrapKey generates a random key of kLen bytes and encrypts it.
	// The returned wrappedKey is the CEK to use for content encryption.
	cek, cipherDER, err := gm.SM9WrapKey(masterPubKey, uid, gm.SM4BlockSize)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to wrap CEK with SM9: %w", err)
	}

	// 2. Build and encode JWE protected header
	if enc == "" {
		enc = SGD_SM4_GCM
	}
	header := jweHeader{
		Algorithm:  SGD_SM9_3,
		Encryption: enc,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to marshal JWE header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// 3. Encrypt content with SM4
	encryptedKeyB64 := base64.RawURLEncoding.EncodeToString(cipherDER)

	var iv []byte
	var sealed []byte

	switch enc {
	case SGD_SM4_GCM:
		iv = make([]byte, gm.SM4GCMNonceSize)
		if _, err := rand.Read(iv); err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to generate IV: %w", err)
		}
		aad := []byte(headerB64)
		sealed, err = gm.SM4EncryptGCMWithNonce(cek, iv, plaintext, aad)
		if err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to encrypt with SM4-GCM: %w", err)
		}
	case SGD_SM4_CCM:
		iv = make([]byte, gm.SM4CCMNonceSize)
		if _, err := rand.Read(iv); err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to generate IV: %w", err)
		}
		aad := []byte(headerB64)
		sealed, err = gm.SM4EncryptCCMWithNonce(cek, iv, plaintext, aad)
		if err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to encrypt with SM4-CCM: %w", err)
		}
	default:
		return "", fmt.Errorf("%w: %s", ErrJWEUnsupportedEnc, enc)
	}

	// 4. Split ciphertext and authentication tag
	tagSize := sm4TagSize(enc)
	if len(sealed) < tagSize {
		return "", errors.New("kexcore/crypto: SM4 output too short")
	}
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	// 5. Build JWE compact serialization
	ivB64 := base64.RawURLEncoding.EncodeToString(iv)
	ciphertextB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	tagB64 := base64.RawURLEncoding.EncodeToString(tag)

	return headerB64 + "." + encryptedKeyB64 + "." + ivB64 + "." + ciphertextB64 + "." + tagB64, nil
}

// SM9DecryptJWE decrypts a GM/T 0125.3 JWE compact serialization
// with SM9 key wrapping (SGD_SM9_3) and SM4 content encryption.
func SM9DecryptJWE(userKey *sm9.EncryptPrivateKey, uid []byte, compact string) ([]byte, error) {
	parts, header, err := ParseJWECompact(compact)
	if err != nil {
		return nil, err
	}

	if header.Algorithm != SGD_SM9_3 {
		return nil, fmt.Errorf("%w: expected alg=%s, got %s", ErrJWEHeaderMismatch, SGD_SM9_3, header.Algorithm)
	}

	// Decode encrypted key (ASN.1 DER)
	cipherDER, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode encrypted key: %w", ErrInvalidJWECompact, err)
	}

	// Unwrap CEK with SM9 private key
	cek, err := gm.SM9UnwrapKey(userKey, uid, cipherDER, gm.SM4BlockSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWEKeyDecrypt, err)
	}

	return decryptJWEContent(cek, header.Encryption, parts)
}

// --- Internal helpers ---

// ParseJWECompact parses and validates a JWE compact serialization.
func ParseJWECompact(compact string) ([]string, *jweHeader, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, nil, ErrInvalidJWEParts
	}

	// All 5 parts must be non-empty per JWE compact serialization
	// Note: ciphertext (part 3) may be empty for zero-length plaintext per RFC 7516
	for i, part := range parts {
		if i == 3 {
			continue // ciphertext may be empty
		}
		if part == "" {
			return nil, nil, fmt.Errorf("%w: part %d is empty", ErrInvalidJWECompact, i)
		}
	}

	// Decode protected header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failed to decode header: %w", ErrInvalidJWECompact, err)
	}

	var header jweHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, fmt.Errorf("%w: failed to parse header: %w", ErrInvalidJWECompact, err)
	}

	return parts, &header, nil
}

// decryptJWEContent decrypts the content portion of a JWE using the recovered CEK.
func decryptJWEContent(cek []byte, enc string, parts []string) ([]byte, error) {
	// Decode IV, ciphertext, and tag
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode IV: %w", ErrInvalidJWECompact, err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode ciphertext: %w", ErrInvalidJWECompact, err)
	}

	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode tag: %w", ErrInvalidJWECompact, err)
	}

	// Reassemble sealed output (ciphertext || tag) for AEAD decryption
	sealed := make([]byte, len(ciphertext)+len(tag))
	copy(sealed, ciphertext)
	copy(sealed[len(ciphertext):], tag)

	// AAD is the base64url-encoded header string per JWE spec
	aad := []byte(parts[0])

	switch enc {
	case SGD_SM4_GCM:
		plaintext, err := gm.SM4DecryptGCMWithNonce(cek, iv, sealed, aad)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrJWEContentDecrypt, err)
		}
		return plaintext, nil
	case SGD_SM4_CCM:
		plaintext, err := gm.SM4DecryptCCMWithNonce(cek, iv, sealed, aad)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrJWEContentDecrypt, err)
		}
		return plaintext, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrJWEUnsupportedEnc, enc)
	}
}

// sm4TagSize returns the authentication tag size for the given SM4 AEAD mode.
func sm4TagSize(enc string) int {
	switch enc {
	case SGD_SM4_GCM:
		return SM4GCMTagSize
	case SGD_SM4_CCM:
		return SM4CCMTagSize
	default:
		return SM4GCMTagSize
	}
}

// --- AES-GCM helpers (standard crypto, used by OIDC verifier for JWE) ---

// AESGCMEncrypt encrypts plaintext using AES-GCM with the given key, nonce, and additional data.
// The key length determines the AES variant (16 bytes = AES-128, 32 bytes = AES-256).
// Returns ciphertext||tag (combined output).
func AESGCMEncrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kexcore/crypto: AES-GCM encrypt: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kexcore/crypto: AES-GCM encrypt: %w", err)
	}
	return aesgcm.Seal(nil, nonce, plaintext, additionalData), nil
}

// AESGCMDecrypt decrypts ciphertext (ciphertext||tag) using AES-GCM with the given key, nonce, and additional data.
// The key length determines the AES variant (16 bytes = AES-128, 32 bytes = AES-256).
func AESGCMDecrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kexcore/crypto: AES-GCM decrypt: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kexcore/crypto: AES-GCM decrypt: %w", err)
	}
	return aesgcm.Open(nil, nonce, ciphertext, additionalData)
}

// --- Dispatch functions: unified entry points that route through ProviderRegistry ---

// DispatchEncryptJWE encrypts plaintext using the specified JWE key wrapping algorithm.
// It checks the ProviderRegistry first; if a provider is registered, it is used.
// Otherwise falls back to the built-in gmsm implementation.
//
// This is the recommended entry point for JWE encryption. Raw functions (SM2EncryptJWE, etc.)
// bypass the registry and should only be called by provider implementations.
func DispatchEncryptJWE(plaintext []byte, key interface{}, alg string) (string, error) {
	if provider, ok := DefaultRegistry.GetJWEEncryptor(alg); ok {
		return provider.Encrypt(context.Background(), plaintext, key)
	}
	return "", fmt.Errorf("no JWE encrypt provider registered for algorithm: %s", alg)
}

// DispatchDecryptJWE decrypts a JWE compact serialization using the specified key wrapping algorithm.
// It checks the ProviderRegistry first; if a provider is registered, it is used.
// Otherwise falls back to the built-in gmsm implementation.
//
// This is the recommended entry point for JWE decryption. Raw functions (SM2DecryptJWE, etc.)
// bypass the registry and should only be called by provider implementations.
func DispatchDecryptJWE(compact string, key interface{}, alg string) ([]byte, error) {
	if provider, ok := DefaultRegistry.GetJWEDecryptor(alg); ok {
		return provider.Decrypt(context.Background(), compact, key)
	}
	return nil, fmt.Errorf("no JWE decrypt provider registered for algorithm: %s", alg)
}

// DispatchContentEncrypt encrypts plaintext using a registered ContentEncryptProvider.
// Falls back to the built-in gmsm AES-GCM/SM4-GCM implementation if no provider is registered.
func DispatchContentEncrypt(enc string, key, iv, plaintext, aad []byte) ([]byte, error) {
	if provider, ok := DefaultRegistry.GetContentEncryptor(enc); ok {
		return provider.Encrypt(context.Background(), key, iv, plaintext, aad)
	}
	return nil, fmt.Errorf("no content encrypt provider registered for: %s", enc)
}

// DispatchContentDecrypt decrypts ciphertext using a registered ContentDecryptProvider.
// Falls back to the built-in gmsm AES-GCM/SM4-GCM implementation if no provider is registered.
func DispatchContentDecrypt(enc string, key, iv, sealed, aad []byte) ([]byte, error) {
	if provider, ok := DefaultRegistry.GetContentDecryptor(enc); ok {
		return provider.Decrypt(context.Background(), key, iv, sealed, aad)
	}
	return nil, fmt.Errorf("no content decrypt provider registered for: %s", enc)
}
