// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
	"github.com/roidmc/kexcore-oidc/pkg/crypto/provider/std"
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

// ParseJWECompact parses and validates a JWE compact serialization.
func ParseJWECompact(compact string) ([]string, *jweHeader, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, nil, ErrInvalidJWEParts
	}
	for i, part := range parts {
		if i == 3 {
			continue
		}
		if part == "" {
			return nil, nil, fmt.Errorf("%w: part %d is empty", ErrInvalidJWECompact, i)
		}
	}
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

// --- Dispatch functions ---

// DispatchEncryptJWE routes JWE encryption through ProviderRegistry.
func DispatchEncryptJWE(plaintext []byte, key interface{}, alg string) (string, error) {
	if provider, ok := DefaultRegistry.GetJWEEncryptor(alg); ok {
		return provider.Encrypt(context.Background(), plaintext, key)
	}
	return "", fmt.Errorf("no JWE encrypt provider registered for algorithm: %s", alg)
}

// DispatchDecryptJWE routes JWE decryption through ProviderRegistry.
func DispatchDecryptJWE(compact string, key interface{}, alg string) ([]byte, error) {
	if provider, ok := DefaultRegistry.GetJWEDecryptor(alg); ok {
		return provider.Decrypt(context.Background(), compact, key)
	}
	return nil, fmt.Errorf("no JWE decrypt provider registered for algorithm: %s", alg)
}

// DispatchContentEncrypt routes content encryption through ProviderRegistry.
func DispatchContentEncrypt(enc string, key, iv, plaintext, aad []byte) ([]byte, error) {
	if provider, ok := DefaultRegistry.GetContentEncryptor(enc); ok {
		return provider.Encrypt(context.Background(), key, iv, plaintext, aad)
	}
	return nil, fmt.Errorf("no content encrypt provider registered for: %s", enc)
}

// DispatchContentDecrypt routes content decryption through ProviderRegistry.
func DispatchContentDecrypt(enc string, key, iv, sealed, aad []byte) ([]byte, error) {
	if provider, ok := DefaultRegistry.GetContentDecryptor(enc); ok {
		return provider.Decrypt(context.Background(), key, iv, sealed, aad)
	}
	return nil, fmt.Errorf("no content decrypt provider registered for: %s", enc)
}

// --- Unified JWE entry points ---

// EncryptJWE encrypts plaintext using the specified JWE algorithms.
// It checks the ProviderRegistry first for HSM/KMS overrides,
// then falls back to the built-in software implementation via crypto/provider/std.
func EncryptJWE(plaintext []byte, key interface{}, alg, enc string) (string, error) {
	if provider, ok := DefaultRegistry.GetJWEEncryptor(alg); ok {
		if provider.ContentEncryption() == enc {
			return provider.Encrypt(context.Background(), plaintext, key)
		}
	}

	switch alg {
	case SGD_SM2_3, SGD_SM9_3:
		return DispatchEncryptJWE(plaintext, key, alg)
	case "dir":
		return encryptJWEDir(plaintext, key, enc)
	case "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW":
		symKey, ok := key.([]byte)
		if !ok {
			return "", fmt.Errorf("%s mode requires []byte key, got %T", alg, key)
		}
		return std.EncryptJWEKW(string(plaintext), symKey, alg, enc)
	case "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512":
		return std.EncryptJWERSAOAEP(string(plaintext), key, alg, enc)
	case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
		return std.EncryptJWEECDHES(string(plaintext), key, alg, enc)
	default:
		return "", fmt.Errorf("unsupported JWE key wrapping algorithm: %s", alg)
	}
}

// DecryptJWE decrypts a JWE compact serialization.
// It checks the ProviderRegistry first for HSM/KMS overrides,
// then falls back to the built-in software implementation.
func DecryptJWE(compact string, key interface{}) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) == 3 {
		return []byte(compact), nil
	}
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWE header: %w", err)
	}
	var hdr jweHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("failed to parse JWE header: %w", err)
	}

	if provider, ok := DefaultRegistry.GetJWEDecryptor(hdr.Algorithm); ok {
		return provider.Decrypt(context.Background(), compact, key)
	}

	switch hdr.Algorithm {
	case SGD_SM2_3, SGD_SM9_3:
		return DispatchDecryptJWE(compact, key, hdr.Algorithm)
	case "dir":
		return decryptJWEDir(compact, key, hdr.Encryption)
	case "A128GCMKW", "A192GCMKW", "A256GCMKW", "A128KW", "A192KW", "A256KW":
		symKey, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%s mode requires []byte key, got %T", hdr.Algorithm, key)
		}
		return std.DecryptJWEKW(compact, symKey, hdr.Algorithm)
	case "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512":
		return std.DecryptJWERSAOAEP(compact, key)
	case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
		return std.DecryptJWEECDHES(compact, key)
	default:
		return nil, fmt.Errorf("unsupported JWE algorithm: %s", hdr.Algorithm)
	}
}

func encryptJWEDir(plaintext []byte, key interface{}, enc string) (string, error) {
	symKey, ok := key.([]byte)
	if !ok {
		return "", fmt.Errorf("dir mode requires []byte key, got %T", key)
	}

	if provider, ok := DefaultRegistry.GetContentEncryptor(enc); ok {
		header := map[string]string{"alg": "dir", "enc": enc}
		headerJSON, err := json.Marshal(header)
		if err != nil {
			return "", err
		}
		headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
		iv := make([]byte, 12)
		if _, err := rand.Read(iv); err != nil {
			return "", err
		}
		sealed, err := provider.Encrypt(context.Background(), symKey, iv, plaintext, []byte(headerB64))
		if err != nil {
			return "", err
		}
		tagSize := 16
		if len(sealed) < tagSize {
			return "", errors.New("encryption output too short")
		}
		ciphertext := sealed[:len(sealed)-tagSize]
		tag := sealed[len(sealed)-tagSize:]
		return headerB64 + ".." +
			base64.RawURLEncoding.EncodeToString(iv) + "." +
			base64.RawURLEncoding.EncodeToString(ciphertext) + "." +
			base64.RawURLEncoding.EncodeToString(tag), nil
	}
	return std.EncryptJWEDir(plaintext, symKey, enc)
}

func decryptJWEDir(compact string, key interface{}, enc string) ([]byte, error) {
	symKey, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("dir mode requires []byte key, got %T", key)
	}
	if provider, ok := DefaultRegistry.GetContentDecryptor(enc); ok {
		parts := strings.Split(compact, ".")
		if parts[1] != "" {
			return nil, errors.New("expected empty encrypted key for dir mode")
		}
		iv, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("failed to decode IV: %w", err)
		}
		ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
		if err != nil {
			return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
		}
		tag, err := base64.RawURLEncoding.DecodeString(parts[4])
		if err != nil {
			return nil, fmt.Errorf("failed to decode tag: %w", err)
		}
		sealed := append(ciphertext, tag...)
		aad := []byte(parts[0])
		return provider.Decrypt(context.Background(), symKey, iv, sealed, aad)
	}
	return std.DecryptJWEDir(compact, symKey, enc)
}

// --- Facade wrappers for content encryption primitives ---
// These delegate to crypto/provider/std so that all standard implementations
// live in one place, while crypto remains the unified entry point.

func AESGCMEncrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	return std.AESGCMEncrypt(key, nonce, plaintext, additionalData)
}

func AESGCMDecrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return std.AESGCMDecrypt(key, nonce, ciphertext, additionalData)
}

func AESCBCEncrypt(enc string, key, iv, plaintext, aad []byte) ([]byte, error) {
	return std.AESCBCEncrypt(enc, key, iv, plaintext, aad)
}

func AESCBCDecrypt(enc string, key, iv, sealed, aad []byte) ([]byte, error) {
	return std.AESCBCDecrypt(enc, key, iv, sealed, aad)
}

// --- SM2 / SM9 JWE facade wrappers ---

func SM2EncryptJWE(publicKey *ecdsa.PublicKey, plaintext []byte) (string, error) {
	return std.EncryptSM2JWE(plaintext, publicKey)
}

func SM2DecryptJWE(privateKey *sm2.PrivateKey, compact string) ([]byte, error) {
	return std.DecryptSM2JWE(compact, privateKey)
}

func SM9EncryptJWE(masterPubKey *sm9.EncryptMasterPublicKey, uid []byte, enc string, plaintext []byte) (string, error) {
	return std.EncryptSM9JWE(plaintext, masterPubKey, uid, enc)
}

func SM9DecryptJWE(userKey *sm9.EncryptPrivateKey, uid []byte, compact string) ([]byte, error) {
	return std.DecryptSM9JWE(compact, userKey, uid)
}
