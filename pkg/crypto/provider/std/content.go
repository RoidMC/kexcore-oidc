// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package std

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"

	"github.com/roidmc/kexcore-oidc/pkg/crypto/gm"
)

// AESGCMEncrypt encrypts plaintext using AES-GCM with the given key, nonce, and additional data.
// The key length determines the AES variant (16 bytes = AES-128, 32 bytes = AES-256).
// Returns ciphertext||tag (combined output).
func AESGCMEncrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kexcore/crypto: AES-GCM encrypt: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kexcore/crypto: AES-GCM encrypt: %w", err)
	}
	return aesgcm.Seal(nil, nonce, plaintext, additionalData), nil
}

// AESGCMDecrypt decrypts ciphertext (ciphertext||tag) using AES-GCM with the given key, nonce, and additional data.
func AESGCMDecrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kexcore/crypto: AES-GCM decrypt: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kexcore/crypto: AES-GCM decrypt: %w", err)
	}
	return aesgcm.Open(nil, nonce, ciphertext, additionalData)
}

// SM4GCMEncrypt encrypts plaintext using SM4-GCM with the given key, nonce, and additional data.
// Returns ciphertext||tag (combined output).
func SM4GCMEncrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	return gm.SM4EncryptGCMWithNonce(key, nonce, plaintext, additionalData)
}

// SM4GCMDecrypt decrypts ciphertext (ciphertext||tag) using SM4-GCM with the given key, nonce, and additional data.
func SM4GCMDecrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return gm.SM4DecryptGCMWithNonce(key, nonce, ciphertext, additionalData)
}

// SM4CCMEncrypt encrypts plaintext using SM4-CCM with the given key, nonce, and additional data.
// Returns ciphertext||tag (combined output).
func SM4CCMEncrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	return gm.SM4EncryptCCMWithNonce(key, nonce, plaintext, additionalData)
}

// SM4CCMDecrypt decrypts ciphertext (ciphertext||tag) using SM4-CCM with the given key, nonce, and additional data.
func SM4CCMDecrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return gm.SM4DecryptCCMWithNonce(key, nonce, ciphertext, additionalData)
}

// --- AES-CBC-HS helpers (RFC 7518 §5.2) ---

type aesCBCParameters struct {
	encKeySize int
	tagSize    int
	macKeySize int
}

var cbcParams = map[string]aesCBCParameters{
	"A128CBC-HS256": {16, 16, 16},
	"A192CBC-HS384": {24, 24, 24},
	"A256CBC-HS512": {32, 32, 32},
}

func newHMACHash(enc string) hash.Hash {
	switch enc {
	case "A192CBC-HS384":
		return hmac.New(sha512.New384, nil)
	case "A256CBC-HS512":
		return hmac.New(sha512.New, nil)
	default:
		return hmac.New(sha256.New, nil)
	}
}

// AESCBCEncrypt encrypts plaintext using AES-CBC with PKCS7 padding, then computes
// an HMAC-SHA authentication tag per RFC 7518 §5.2.
// Returns ciphertext||tag (combined output).
// enc identifies the algorithm: "A128CBC-HS256", "A192CBC-HS384", or "A256CBC-HS512".
func AESCBCEncrypt(enc string, key, iv, plaintext, aad []byte) ([]byte, error) {
	params, ok := cbcParams[enc]
	if !ok {
		return nil, fmt.Errorf("kexcore/crypto: unsupported CBC enc: %s", enc)
	}
	if len(key) != params.encKeySize+params.macKeySize {
		return nil, fmt.Errorf("kexcore/crypto: invalid key length for %s: got %d, want %d", enc, len(key), params.encKeySize+params.macKeySize)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("kexcore/crypto: invalid IV length for CBC: got %d, want %d", len(iv), aes.BlockSize)
	}

	encKey := key[params.macKeySize:]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("kexcore/crypto: AES-CBC encrypt: %w", err)
	}

	// PKCS7 padding
	padLen := aes.BlockSize - (len(plaintext)%aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	ciphertext := make([]byte, len(padded))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, padded)

	// Compute HMAC-SHA per RFC 7518 §5.2.2.1
	al := make([]byte, 8)
	l := len(aad) * 8
	al[0] = byte(l >> 56)
	al[1] = byte(l >> 48)
	al[2] = byte(l >> 40)
	al[3] = byte(l >> 32)
	al[4] = byte(l >> 24)
	al[5] = byte(l >> 16)
	al[6] = byte(l >> 8)
	al[7] = byte(l)

	hmacHash := newHMACHash(enc)
	hmacHash.Write(aad)
	hmacHash.Write(iv)
	hmacHash.Write(ciphertext)
	hmacHash.Write(al)
	fullMAC := hmacHash.Sum(nil)
	tag := fullMAC[:params.tagSize]

	result := make([]byte, len(ciphertext)+len(tag))
	copy(result, ciphertext)
	copy(result[len(ciphertext):], tag)
	return result, nil
}

// AESCBCDecrypt verifies the HMAC tag and decrypts AES-CBC ciphertext with PKCS7 unpadding.
// Input sealed is ciphertext||tag (combined output).
func AESCBCDecrypt(enc string, key, iv, sealed, aad []byte) ([]byte, error) {
	params, ok := cbcParams[enc]
	if !ok {
		return nil, fmt.Errorf("kexcore/crypto: unsupported CBC enc: %s", enc)
	}
	if len(key) != params.encKeySize+params.macKeySize {
		return nil, fmt.Errorf("kexcore/crypto: invalid key length for %s: got %d, want %d", enc, len(key), params.encKeySize+params.macKeySize)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("kexcore/crypto: invalid IV length for CBC: got %d, want %d", len(iv), aes.BlockSize)
	}
	if len(sealed) < params.tagSize {
		return nil, errors.New("kexcore/crypto: CBC sealed data too short")
	}

	encKey := key[params.macKeySize:]

	tagOffset := len(sealed) - params.tagSize
	ciphertext := sealed[:tagOffset]
	receivedTag := sealed[tagOffset:]

	// Verify HMAC
	al := make([]byte, 8)
	l := len(aad) * 8
	al[0] = byte(l >> 56)
	al[1] = byte(l >> 48)
	al[2] = byte(l >> 40)
	al[3] = byte(l >> 32)
	al[4] = byte(l >> 24)
	al[5] = byte(l >> 16)
	al[6] = byte(l >> 8)
	al[7] = byte(l)

	hmacHash := newHMACHash(enc)
	hmacHash.Write(aad)
	hmacHash.Write(iv)
	hmacHash.Write(ciphertext)
	hmacHash.Write(al)
	fullMAC := hmacHash.Sum(nil)
	expectedTag := fullMAC[:params.tagSize]

	if subtle.ConstantTimeCompare(receivedTag, expectedTag) != 1 {
		return nil, errors.New("kexcore/crypto: CBC authentication tag mismatch")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("kexcore/crypto: AES-CBC decrypt: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("kexcore/crypto: CBC ciphertext not a multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	if len(plaintext) == 0 {
		return plaintext, nil
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(plaintext) {
		return nil, errors.New("kexcore/crypto: invalid PKCS7 padding")
	}
	for i := len(plaintext) - padLen; i < len(plaintext); i++ {
		if plaintext[i] != byte(padLen) {
			return nil, errors.New("kexcore/crypto: invalid PKCS7 padding")
		}
	}
	return plaintext[:len(plaintext)-padLen], nil
}
