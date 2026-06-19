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

	"github.com/emmansun/gmsm/sm9"
	"github.com/roidmc/kexcore-oidc/v2/pkg/crypto/gm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/crypto/util"
)

// EncryptSM9JWE encrypts plaintext using the GM/T 0125.3 JWE specification
// with SM9 key wrapping (SGD_SM9_3) and SM4 content encryption.
func EncryptSM9JWE(plaintext []byte, key interface{}, uid []byte, enc string) (string, error) {
	masterPubKey, ok := key.(*sm9.EncryptMasterPublicKey)
	if !ok {
		return "", fmt.Errorf("SM9 JWE requires *sm9.EncryptMasterPublicKey, got %T", key)
	}

	cek, cipherDER, err := gm.SM9WrapKey(masterPubKey, uid, gm.SM4BlockSize)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to wrap CEK with SM9: %w", err)
	}

	if enc == "" {
		enc = sgdSM4_GCM
	}
	header := util.JWEHeader{Algorithm: sgdSM9_3, Encryption: enc}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to marshal JWE header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	encryptedKeyB64 := base64.RawURLEncoding.EncodeToString(cipherDER)

	var iv []byte
	var sealed []byte

	aad := []byte(headerB64)
	switch enc {
	case sgdSM4_GCM:
		iv = make([]byte, gm.SM4GCMNonceSize)
		if _, err := rand.Read(iv); err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to generate IV: %w", err)
		}
		sealed, err = SM4GCMEncrypt(cek, iv, plaintext, aad)
		if err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to encrypt with SM4-GCM: %w", err)
		}
	case sgdSM4_CCM:
		iv = make([]byte, gm.SM4CCMNonceSize)
		if _, err := rand.Read(iv); err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to generate IV: %w", err)
		}
		sealed, err = SM4CCMEncrypt(cek, iv, plaintext, aad)
		if err != nil {
			return "", fmt.Errorf("kexcore/crypto: failed to encrypt with SM4-CCM: %w", err)
		}
	default:
		return "", fmt.Errorf("%w: %s", util.ErrJWEUnsupportedEnc, enc)
	}

	tagSize := sm4TagSize(enc)
	if len(sealed) < tagSize {
		return "", errors.New("kexcore/crypto: SM4 output too short")
	}
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	ivB64 := base64.RawURLEncoding.EncodeToString(iv)
	ciphertextB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	tagB64 := base64.RawURLEncoding.EncodeToString(tag)

	return headerB64 + "." + encryptedKeyB64 + "." + ivB64 + "." + ciphertextB64 + "." + tagB64, nil
}

// DecryptSM9JWE decrypts a GM/T 0125.3 JWE compact serialization with SM9 key wrapping.
func DecryptSM9JWE(compact string, key interface{}, uid []byte) ([]byte, error) {
	userKey, ok := key.(*sm9.EncryptPrivateKey)
	if !ok {
		return nil, fmt.Errorf("SM9 JWE requires *sm9.EncryptPrivateKey, got %T", key)
	}

	parts, header, err := util.ParseJWECompact(compact)
	if err != nil {
		return nil, err
	}
	if header.Algorithm != sgdSM9_3 {
		return nil, fmt.Errorf("%w: expected alg=%s, got %s", util.ErrJWEHeaderMismatch, sgdSM9_3, header.Algorithm)
	}

	cipherDER, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode encrypted key: %w", util.ErrInvalidJWECompact, err)
	}

	cek, err := gm.SM9UnwrapKey(userKey, uid, cipherDER, gm.SM4BlockSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", util.ErrJWEKeyDecrypt, err)
	}

	return decryptJWEContent(cek, header.Encryption, parts)
}
