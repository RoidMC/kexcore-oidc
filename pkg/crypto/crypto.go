// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/roidmc/kexcore-oidc/pkg/crypto/provider/std"
)

var (
	ErrCipherTextTooShort = errors.New("kexcore/crypto: ciphertext too short")
	ErrInvalidAESKeySize  = errors.New("kexcore/crypto: aes invalid key size, must be 16, 24, or 32 bytes")
)

const (
	AESGCMNonceSize = 12
)

func EncryptAES(data string, key string) (string, error) {
	encrypted, err := EncryptBytesAES([]byte(data), key)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func EncryptBytesAES(plainText []byte, key string) ([]byte, error) {
	symKey := []byte(key)
	nonce := make([]byte, AESGCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed, err := std.AESGCMEncrypt(symKey, nonce, plainText, nil)
	if err != nil {
		return nil, err
	}
	result := make([]byte, AESGCMNonceSize+len(sealed))
	copy(result[:AESGCMNonceSize], nonce)
	copy(result[AESGCMNonceSize:], sealed)
	return result, nil
}

func DecryptAES(data string, key string) (string, error) {
	text, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	decrypted, err := DecryptBytesAES(text, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func DecryptBytesAES(cipherText []byte, key string) ([]byte, error) {
	if len(cipherText) < AESGCMNonceSize {
		return nil, ErrCipherTextTooShort
	}
	nonce := cipherText[:AESGCMNonceSize]
	sealed := cipherText[AESGCMNonceSize:]
	return std.AESGCMDecrypt([]byte(key), nonce, sealed, nil)
}

func EncryptSM4(data string, key string) (string, error) {
	encrypted, err := EncryptBytesSM4([]byte(data), key)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func EncryptBytesSM4(plainText []byte, key string) ([]byte, error) {
	symKey := []byte(key)
	iv := make([]byte, AESGCMNonceSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	sealed, err := std.SM4GCMEncrypt(symKey, iv, plainText, nil)
	if err != nil {
		return nil, err
	}
	result := make([]byte, AESGCMNonceSize+len(sealed))
	copy(result[:AESGCMNonceSize], iv)
	copy(result[AESGCMNonceSize:], sealed)
	return result, nil
}

func DecryptSM4(data string, key string) (string, error) {
	text, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	decrypted, err := DecryptBytesSM4(text, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func DecryptBytesSM4(cipherText []byte, key string) ([]byte, error) {
	symKey := []byte(key)
	if len(cipherText) < AESGCMNonceSize {
		return nil, ErrCipherTextTooShort
	}
	iv := cipherText[:AESGCMNonceSize]
	sealed := cipherText[AESGCMNonceSize:]
	return std.SM4GCMDecrypt(symKey, iv, sealed, nil)
}
