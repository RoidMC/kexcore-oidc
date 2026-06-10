// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package std

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// EncryptJWEDir encrypts plaintext using direct key agreement (alg=dir).
func EncryptJWEDir(plaintext []byte, symKey []byte, enc string) (string, error) {
	header := map[string]string{"alg": "dir", "enc": enc}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	var nonceSize int
	switch enc {
	case "A128GCM", "A192GCM", "A256GCM", sgdSM4_GCM:
		nonceSize = 12
	case sgdSM4_CCM:
		nonceSize = 12 // SM4 CCM nonce size
	default:
		return "", fmt.Errorf("unsupported dir mode enc: %s", enc)
	}

	iv := make([]byte, nonceSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	var sealed []byte
	aad := []byte(headerB64)
	switch enc {
	case "A128GCM", "A192GCM", "A256GCM":
		sealed, err = AESGCMEncrypt(symKey, iv, plaintext, aad)
	case sgdSM4_GCM:
		sealed, err = SM4GCMEncrypt(symKey, iv, plaintext, aad)
	case sgdSM4_CCM:
		sealed, err = SM4CCMEncrypt(symKey, iv, plaintext, aad)
	default:
		return "", fmt.Errorf("unsupported dir mode enc: %s", enc)
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

// DecryptJWEDir decrypts a JWE compact serialization with direct key agreement (alg=dir).
func DecryptJWEDir(compact string, symKey []byte, enc string) ([]byte, error) {
	parts := parseCompactParts(compact)
	if parts == nil {
		return nil, errors.New("invalid JWE compact serialization")
	}
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
	case "A128GCM", "A192GCM", "A256GCM":
		return AESGCMDecrypt(symKey, iv, sealed, aad)
	case sgdSM4_GCM:
		return SM4GCMDecrypt(symKey, iv, sealed, aad)
	case sgdSM4_CCM:
		return SM4CCMDecrypt(symKey, iv, sealed, aad)
	default:
		return nil, fmt.Errorf("unsupported dir mode enc: %s", enc)
	}
}

func parseCompactParts(compact string) []string {
	parts := make([]string, 5)
	s := compact
	for i := 0; i < 4; i++ {
		idx := findDot(s)
		if idx == -1 {
			return nil
		}
		parts[i] = s[:idx]
		s = s[idx+1:]
	}
	parts[4] = s
	return parts
}

func findDot(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}
