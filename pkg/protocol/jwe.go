// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package protocol

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/roidmc/kexcore-oidc/pkg/crypto"
)

// SM9EncryptKey is the protocol-layer interface for SM9 encryption keys.
// It hides the underlying gmsm type from protocol consumers.
// Implementations are provided by pkg/crypto (gmsm) or HSM adapters.
//
// The canonical implementation is crypto.SM9MasterPublicKey, which wraps
// *sm9.EncryptMasterPublicKey + UID. HSM/KMS vendors can implement this
// interface to provide their own SM9 key material.
type SM9EncryptKey interface {
	// MarshalBinary returns the SM9 master public key in its canonical byte representation.
	MarshalBinary() ([]byte, error)
	// GetUID returns the user identifier for SM9 identity-based encryption.
	GetUID() []byte
}

// JWEService is the unified entry point for JWE encryption and decryption.
// Both OP and RP can use it without caring about the underlying implementation.
type JWEService interface {
	// Encrypt encrypts plaintext using the specified JWE algorithms.
	// alg is the key wrapping algorithm (e.g. "dir", "SGD_SM2_3", "SGD_SM9_3").
	// enc is the content encryption algorithm (e.g. "A256GCM", "SGD_SM4_GCM").
	// key is the encryption key material; type depends on alg:
	//   - "dir": []byte symmetric key
	//   - "SGD_SM2_3": *ecdsa.PublicKey
	//   - "SGD_SM9_3": SM9EncryptKey
	Encrypt(ctx context.Context, plaintext []byte, key interface{}, alg, enc string) (string, error)

	// Decrypt decrypts a JWE compact serialization.
	// key is the decryption key material; type depends on the JWE header alg.
	Decrypt(ctx context.Context, token string, key interface{}) ([]byte, error)
}

// EncryptTokenJWE encrypts a signed JWT using the specified JWE algorithm.
// It dispatches to the crypto provider registry for GM/T algorithms,
// and handles standard algorithms (dir, A256GCMKW) locally.
//
// This function replaces the previous EncryptTokenSM2/EncryptTokenSM9 functions,
// providing a single entry point for all JWE encryption.
func EncryptTokenJWE(signedToken string, key interface{}, alg, enc string) (string, error) {
	switch alg {
	case JWEAlgSM23, JWEAlgSM93:
		if provider, ok := crypto.DefaultRegistry.GetJWEEncryptor(alg); ok {
			return provider.Encrypt(context.Background(), []byte(signedToken), key)
		}
		return "", fmt.Errorf("no JWE encrypt provider registered for algorithm: %s", alg)

	case JWEAlgDir:
		return encryptTokenDir(signedToken, key, enc)

	case JWEAlgA256GCMKW:
		return encryptA256GCMKW(signedToken, key)

	default:
		return "", fmt.Errorf("unsupported JWE key wrapping algorithm: %s", alg)
	}
}

// DecryptTokenJWE decrypts a JWE compact serialization.
// It dispatches to the crypto provider registry for GM/T algorithms,
// and handles standard algorithms locally.
func DecryptTokenJWE(compact string, key interface{}) ([]byte, error) {
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
	var hdr struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("failed to parse JWE header: %w", err)
	}

	switch hdr.Alg {
	case JWEAlgSM23, JWEAlgSM93:
		if provider, ok := crypto.DefaultRegistry.GetJWEDecryptor(hdr.Alg); ok {
			return provider.Decrypt(context.Background(), compact, key)
		}
		return nil, fmt.Errorf("no JWE decrypt provider registered for algorithm: %s", hdr.Alg)

	case JWEAlgDir:
		symKey, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("dir mode requires []byte key, got %T", key)
		}
		return decryptDirMode(compact, symKey, hdr.Enc)

	case JWEAlgA256GCMKW:
		symKey, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("A256GCMKW mode requires []byte key, got %T", key)
		}
		return decryptAESGCMKW(compact, symKey)

	default:
		return nil, fmt.Errorf("unsupported JWE algorithm: %s", hdr.Alg)
	}
}

// encryptTokenDir performs direct symmetric encryption (alg=dir) of a payload.
func encryptTokenDir(payload string, key interface{}, enc string) (string, error) {
	symKey, ok := key.([]byte)
	if !ok {
		return "", fmt.Errorf("dir mode requires []byte key, got %T", key)
	}

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
	var sealed []byte
	switch enc {
	case JWEEncSM4GCM:
		sealed, err = crypto.SM4EncryptGCMWithNonce(symKey, iv, []byte(payload), []byte(headerB64))
	case JWEEncA128GCM, JWEEncA256GCM:
		sealed, err = crypto.AESGCMEncrypt(symKey, iv, []byte(payload), []byte(headerB64))
	default:
		return "", fmt.Errorf("unsupported JWE content encryption: %s", enc)
	}
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

// decryptDirMode decrypts a JWE in dir mode.
func decryptDirMode(compact string, key []byte, enc string) ([]byte, error) {
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
	switch enc {
	case JWEEncSM4GCM:
		plaintext, err := crypto.SM4DecryptGCMWithNonce(key, iv, sealed, aad)
		if err != nil {
			return nil, fmt.Errorf("sm4-gcm decrypt failed: %w", err)
		}
		return plaintext, nil
	case JWEEncA128GCM, JWEEncA256GCM:
		plaintext, err := crypto.AESGCMDecrypt(key, iv, sealed, aad)
		if err != nil {
			return nil, fmt.Errorf("aes-gcm decrypt failed: %w", err)
		}
		return plaintext, nil
	default:
		return nil, fmt.Errorf("unsupported JWE content encryption: %s", enc)
	}
}

// decryptAESGCMKW decrypts a JWE using A256GCMKW key wrapping.
func decryptAESGCMKW(compact string, key []byte) ([]byte, error) {
	jk, err := jwk.Import[jwk.SymmetricKey](key)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %w", err)
	}
	decrypted, err := jwe.Decrypt([]byte(compact), jwe.WithKey(jwa.A256GCMKW(), jk))
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// encryptA256GCMKW encrypts using A256GCMKW key wrapping.
func encryptA256GCMKW(signedToken string, key interface{}) (string, error) {
	symKey, ok := key.([]byte)
	if !ok {
		return "", fmt.Errorf("A256GCMKW mode requires []byte key, got %T", key)
	}
	jk, err := jwk.Import[jwk.SymmetricKey](symKey)
	if err != nil {
		return "", fmt.Errorf("failed to create key: %w", err)
	}
	encrypted, err := jwe.Encrypt([]byte(signedToken), jwe.WithKey(jwa.A256GCMKW(), jk), jwe.WithContentEncryption(jwa.A256GCM()))
	if err != nil {
		return "", fmt.Errorf("A256GCMKW encryption failed: %w", err)
	}
	return string(encrypted), nil
}
