// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package std

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/emmansun/gmsm/sm2"
	"github.com/roidmc/kexcore-oidc/v3/pkg/crypto/gm"
	"github.com/roidmc/kexcore-oidc/v3/pkg/crypto/util"
)

// EncryptSM2JWE encrypts plaintext using the GM/T 0125.3 JWE specification
// with SM2 key wrapping (SGD_SM2_3) and SM4-GCM content encryption (SGD_SM4_GCM).
func EncryptSM2JWE(plaintext []byte, key interface{}) (string, error) {
	return EncryptSM2JWEWith(plaintext, key, sgdSM4_GCM)
}

// EncryptSM2JWEWith encrypts plaintext with SM2 key wrapping and the requested
// SM4 content encryption algorithm (SGD_SM4_GCM or SGD_SM4_CCM).
func EncryptSM2JWEWith(plaintext []byte, key interface{}, enc string) (string, error) {
	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("SM2 JWE requires *ecdsa.PublicKey, got %T", key)
	}
	if enc == "" {
		enc = sgdSM4_GCM
	}
	if enc != sgdSM4_GCM && enc != sgdSM4_CCM {
		return "", fmt.Errorf("%w: %s", util.ErrJWEUnsupportedEnc, enc)
	}

	cek := make([]byte, gm.SM4BlockSize)
	if _, err := rand.Read(cek); err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to generate CEK: %w", err)
	}

	ivLen := gm.SM4GCMNonceSize
	if enc == sgdSM4_CCM {
		ivLen = gm.SM4CCMNonceSize
	}
	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to generate IV: %w", err)
	}

	header := util.JWEHeader{Algorithm: sgdSM2_3, Encryption: enc}
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
	var sealed []byte
	switch enc {
	case sgdSM4_GCM:
		sealed, err = SM4GCMEncrypt(cek, iv, plaintext, aad)
	case sgdSM4_CCM:
		sealed, err = SM4CCMEncrypt(cek, iv, plaintext, aad)
	}
	if err != nil {
		return "", fmt.Errorf("kexcore/crypto: failed to encrypt with content encryption %s: %w", enc, err)
	}

	tagSize := sm4TagSize(enc)
	if len(sealed) < tagSize {
		return "", fmt.Errorf("kexcore/crypto: %s output too short", enc)
	}
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

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

	parts, header, err := util.ParseJWECompact(compact)
	if err != nil {
		return nil, err
	}
	if header.Algorithm != sgdSM2_3 {
		return nil, fmt.Errorf("%w: expected alg=%s, got %s", util.ErrJWEHeaderMismatch, sgdSM2_3, header.Algorithm)
	}

	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode encrypted key: %w", util.ErrInvalidJWECompact, err)
	}

	cek, err := gm.SM2Decrypt(privKey, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", util.ErrJWEKeyDecrypt, err)
	}

	return decryptJWEContent(cek, header.Encryption, parts)
}
