// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var ErrCipherTextBlockSize = errors.New("ciphertext block size is too short")

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

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return cipherText, nil
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

	if len(cipherText) < aes.BlockSize {
		return nil, ErrCipherTextBlockSize
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return cipherText, err
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
