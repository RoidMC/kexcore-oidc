// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
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
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, AESGCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plainText, nil)

	result := make([]byte, AESGCMNonceSize+len(ciphertext))
	copy(result[:AESGCMNonceSize], nonce)
	copy(result[AESGCMNonceSize:], ciphertext)

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
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(cipherText) < AESGCMNonceSize {
		return nil, ErrCipherTextTooShort
	}

	nonce := cipherText[:AESGCMNonceSize]
	cipherText = cipherText[AESGCMNonceSize:]

	return aesgcm.Open(nil, nonce, cipherText, nil)
}

func EncryptSM4(data string, key string) (string, error) {
	encrypted, err := EncryptBytesSM4([]byte(data), key)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func EncryptBytesSM4(plainText []byte, key string) ([]byte, error) {
	return SM4EncryptGCM([]byte(key), plainText, nil)
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
	return SM4DecryptGCM([]byte(key), cipherText, nil)
}
