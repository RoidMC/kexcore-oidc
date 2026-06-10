// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package std

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/emmansun/gmsm/sm2"
	"github.com/roidmc/kexcore-oidc/pkg/crypto/gm"
)

// EncryptSM2JWE encrypts plaintext using the GM/T 0125.3 JWE specification
// with SM2 key wrapping (SGD_SM2_3) and SM4-GCM content encryption (SGD_SM4_GCM).
func EncryptSM2JWE(plaintext []byte, key interface{}) (string, error) {
	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("SM2 JWE requires *ecdsa.PublicKey, got %T", key)
	}

	cek := make([]byte, gm.SM4BlockSize)
	if _, err := rand.Read(cek); err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to generate CEK: %w", err)
	}

	iv := make([]byte, gm.SM4GCMNonceSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to generate IV: %w", err)
	}

	header := jweHeader{Algorithm: sgdSM2_3, Encryption: sgdSM4_GCM}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to marshal JWE header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	encryptedKey, err := gm.SM2EncryptASN1(pubKey, cek)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to wrap CEK with SM2: %w", err)
	}
	encryptedKeyB64 := base64.RawURLEncoding.EncodeToString(encryptedKey)

	aad := []byte(headerB64)
	sealed, err := SM4GCMEncrypt(cek, iv, plaintext, aad)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to encrypt with SM4-GCM: %w", err)
	}

	if len(sealed) < sm4GCMTagSize {
		return "", errors.New("kexcore/crypto: SM4-GCM output too short")
	}
	ciphertext := sealed[:len(sealed)-sm4GCMTagSize]
	tag := sealed[len(sealed)-sm4GCMTagSize:]

	ivB64 := base64.RawURLEncoding.EncodeToString(iv)
	ciphertextB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	tagB64 := base64.RawURLEncoding.EncodeToString(tag)

	return headerB64 + "." + encryptedKeyB64 + "." + ivB64 + "." + ciphertextB64 + "." + tagB64, nil
}

// DecryptSM2JWE decrypts a GM/T 0125.3 JWE compact serialization with SM2 key wrapping.
func DecryptSM2JWE(compact string, key interface{}) ([]byte, error) {
	privKey, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("SM2 JWE requires *sm2.PrivateKey, got %T", key)
	}

	parts, header, err := parseJWECompact(compact)
	if err != nil {
		return nil, err
	}
	if header.Algorithm != sgdSM2_3 {
		return nil, fmt.Errorf("%w: expected alg=%s, got %s", errJWEHeaderMismatch, sgdSM2_3, header.Algorithm)
	}

	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode encrypted key: %w", errInvalidJWECompact, err)
	}

	cek, err := gm.SM2Decrypt(privKey, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errJWEKeyDecrypt, err)
	}

	return decryptJWEContent(cek, header.Encryption, parts)
}
