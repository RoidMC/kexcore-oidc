// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
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
	cek := make([]byte, SM4BlockSize)
	if _, err := rand.Read(cek); err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to generate CEK: %w", err)
	}

	// 2. Generate random IV (96 bits for GCM)
	iv := make([]byte, SM4GCMNonceSize)
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
	encryptedKey, err := SM2EncryptASN1(publicKey, cek)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to wrap CEK with SM2: %w", err)
	}
	encryptedKeyB64 := base64.RawURLEncoding.EncodeToString(encryptedKey)

	// 5. Encrypt plaintext with SM4-GCM using AAD = headerB64
	aad := []byte(headerB64)
	sealed, err := SM4EncryptGCMWithNonce(cek, iv, plaintext, aad)
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
	parts, header, err := parseJWECompact(compact)
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
	cek, err := SM2Decrypt(privateKey, encryptedKey)
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
	cek, cipherDER, err := SM9WrapKey(masterPubKey, uid, SM4BlockSize)
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
		iv = make([]byte, SM4GCMNonceSize)
		if _, err := rand.Read(iv); err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to generate IV: %w", err)
		}
		aad := []byte(headerB64)
		sealed, err = SM4EncryptGCMWithNonce(cek, iv, plaintext, aad)
		if err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to encrypt with SM4-GCM: %w", err)
		}
	case SGD_SM4_CCM:
		iv = make([]byte, SM4CCMNonceSize)
		if _, err := rand.Read(iv); err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to generate IV: %w", err)
		}
		aad := []byte(headerB64)
		sealed, err = SM4EncryptCCMWithNonce(cek, iv, plaintext, aad)
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
	parts, header, err := parseJWECompact(compact)
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
	cek, err := SM9UnwrapKey(userKey, uid, cipherDER, SM4BlockSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWEKeyDecrypt, err)
	}

	return decryptJWEContent(cek, header.Encryption, parts)
}

// --- Internal helpers ---

// parseJWECompact parses and validates a JWE compact serialization.
func parseJWECompact(compact string) ([]string, *jweHeader, error) {
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
		plaintext, err := SM4DecryptGCMWithNonce(cek, iv, sealed, aad)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrJWEContentDecrypt, err)
		}
		return plaintext, nil
	case SGD_SM4_CCM:
		plaintext, err := SM4DecryptCCMWithNonce(cek, iv, sealed, aad)
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
