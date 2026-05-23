// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/sm4"

	gmcipher "github.com/emmansun/gmsm/cipher"
)

var (
	ErrInvalidSM4KeySize    = errors.New("kexcore/crypto: sm4 invalid key size, must be 16 bytes")
	ErrInvalidSM4IVSize     = errors.New("kexcore/crypto: sm4 invalid IV size, must be 16 bytes")
	ErrInvalidSM4NonceSize  = errors.New("kexcore/crypto: sm4 invalid nonce size for GCM, must be 12 bytes")
	ErrInvalidCiphertextLen = errors.New("kexcore/crypto: sm4 ciphertext is not a multiple of the block size")
)

const (
	SM4BlockSize    = sm4.BlockSize
	SM4GCMNonceSize = 12
	SM4CCMNonceSize = 12
)

var sm4PKCS7 = padding.NewPKCS7Padding(uint(SM4BlockSize))

func SM4GenerateKey() ([]byte, error) {
	key := make([]byte, SM4BlockSize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func SM4NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != SM4BlockSize {
		return nil, ErrInvalidSM4KeySize
	}
	return sm4.NewCipher(key)
}

// SM4EncryptECB encrypts plaintext using SM4 in ECB mode.
// WARNING: ECB mode is NOT secure for most use cases. It does not provide
// semantic security and leaks data patterns. Use CBC or GCM mode instead.
// This function is provided for compatibility with legacy systems only.
func SM4EncryptECB(key, plaintext []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded := sm4PKCS7.Pad(plaintext)
	ciphertext := make([]byte, len(padded))

	for i := 0; i < len(padded); i += SM4BlockSize {
		block.Encrypt(ciphertext[i:i+SM4BlockSize], padded[i:i+SM4BlockSize])
	}

	return ciphertext, nil
}

// SM4DecryptECB decrypts ciphertext using SM4 in ECB mode.
// WARNING: ECB mode is NOT secure. See SM4EncryptECB for details.
func SM4DecryptECB(key, ciphertext []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%SM4BlockSize != 0 {
		return nil, ErrInvalidCiphertextLen
	}

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += SM4BlockSize {
		block.Decrypt(plaintext[i:i+SM4BlockSize], ciphertext[i:i+SM4BlockSize])
	}

	return sm4PKCS7.ConstantTimeUnpad(plaintext)
}

// SM4EncryptCBC encrypts plaintext using SM4 in CBC mode.
// The IV is randomly generated and prepended to the ciphertext.
// Returns: IV || ciphertext
func SM4EncryptCBC(key, plaintext []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, SM4BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	padded := sm4PKCS7.Pad(plaintext)
	ciphertext := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:SM4BlockSize], iv)
	copy(result[SM4BlockSize:], ciphertext)

	return result, nil
}

// SM4DecryptCBC decrypts ciphertext using SM4 in CBC mode.
// Expects: IV || ciphertext format.
func SM4DecryptCBC(key, ciphertext []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < SM4BlockSize {
		return nil, errors.New("kexcore/crypto: sm4 ciphertext too short")
	}

	if len(ciphertext)%SM4BlockSize != 0 {
		return nil, ErrInvalidCiphertextLen
	}

	iv := ciphertext[:SM4BlockSize]
	ciphertext = ciphertext[SM4BlockSize:]

	plaintext := make([]byte, len(ciphertext))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return sm4PKCS7.ConstantTimeUnpad(plaintext)
}

// SM4EncryptCBCWithIV encrypts plaintext using SM4 in CBC mode with provided IV.
// Use SM4EncryptCBC for automatic IV generation.
func SM4EncryptCBCWithIV(key, iv, plaintext []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != SM4BlockSize {
		return nil, ErrInvalidSM4IVSize
	}

	padded := sm4PKCS7.Pad(plaintext)
	ciphertext := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

// SM4DecryptCBCWithIV decrypts ciphertext using SM4 in CBC mode with provided IV.
func SM4DecryptCBCWithIV(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != SM4BlockSize {
		return nil, ErrInvalidSM4IVSize
	}

	if len(ciphertext)%SM4BlockSize != 0 {
		return nil, ErrInvalidCiphertextLen
	}

	plaintext := make([]byte, len(ciphertext))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return sm4PKCS7.ConstantTimeUnpad(plaintext)
}

// SM4EncryptGCM encrypts plaintext using SM4 in GCM mode.
// The nonce is randomly generated and prepended to the ciphertext.
// Returns: nonce || ciphertext (with auth tag)
func SM4EncryptGCM(key, plaintext, additionalData []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, SM4GCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, additionalData)

	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:SM4GCMNonceSize], nonce)
	copy(result[SM4GCMNonceSize:], ciphertext)

	return result, nil
}

// SM4DecryptGCM decrypts ciphertext using SM4 in GCM mode.
// Expects: nonce || ciphertext format.
func SM4DecryptGCM(key, ciphertext, additionalData []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < SM4GCMNonceSize {
		return nil, errors.New("kexcore/crypto: sm4 gcm ciphertext too short")
	}

	nonce := ciphertext[:SM4GCMNonceSize]
	ciphertext = ciphertext[SM4GCMNonceSize:]

	return aesgcm.Open(nil, nonce, ciphertext, additionalData)
}

// SM4EncryptGCMWithNonce encrypts plaintext using SM4 in GCM mode with provided nonce.
// WARNING: Never reuse a nonce with the same key. Use SM4EncryptGCM for automatic nonce generation.
func SM4EncryptGCMWithNonce(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != SM4GCMNonceSize {
		return nil, ErrInvalidSM4NonceSize
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Seal(nil, nonce, plaintext, additionalData), nil
}

// SM4DecryptGCMWithNonce decrypts ciphertext using SM4 in GCM mode with provided nonce.
func SM4DecryptGCMWithNonce(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != SM4GCMNonceSize {
		return nil, ErrInvalidSM4NonceSize
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext, additionalData)
}

func SM4KeyToHex(key []byte) string {
	return hex.EncodeToString(key)
}

func SM4KeyFromHex(hexKey string) ([]byte, error) {
	return hex.DecodeString(hexKey)
}

// SM4EncryptCCM encrypts plaintext using SM4 in CCM mode.
// The nonce is randomly generated and prepended to the ciphertext.
// Returns: nonce || ciphertext (with auth tag)
func SM4EncryptCCM(key, plaintext, additionalData []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	ccm, err := gmcipher.NewCCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, SM4CCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := ccm.Seal(nil, nonce, plaintext, additionalData)

	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:SM4CCMNonceSize], nonce)
	copy(result[SM4CCMNonceSize:], ciphertext)

	return result, nil
}

// SM4DecryptCCM decrypts ciphertext using SM4 in CCM mode.
// Expects: nonce || ciphertext format.
func SM4DecryptCCM(key, ciphertext, additionalData []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	ccm, err := gmcipher.NewCCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < SM4CCMNonceSize {
		return nil, errors.New("kexcore/crypto: sm4 ccm ciphertext too short")
	}

	nonce := ciphertext[:SM4CCMNonceSize]
	ciphertext = ciphertext[SM4CCMNonceSize:]

	return ccm.Open(nil, nonce, ciphertext, additionalData)
}

// SM4EncryptCCMWithNonce encrypts plaintext using SM4 in CCM mode with provided nonce.
// WARNING: Never reuse a nonce with the same key. Use SM4EncryptCCM for automatic nonce generation.
func SM4EncryptCCMWithNonce(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != SM4CCMNonceSize {
		return nil, errors.New("kexcore/crypto: sm4 invalid nonce size for CCM, must be 12 bytes")
	}

	ccm, err := gmcipher.NewCCM(block)
	if err != nil {
		return nil, err
	}

	return ccm.Seal(nil, nonce, plaintext, additionalData), nil
}

// SM4DecryptCCMWithNonce decrypts ciphertext using SM4 in CCM mode with provided nonce.
func SM4DecryptCCMWithNonce(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	block, err := SM4NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != SM4CCMNonceSize {
		return nil, errors.New("kexcore/crypto: sm4 invalid nonce size for CCM, must be 12 bytes")
	}

	ccm, err := gmcipher.NewCCM(block)
	if err != nil {
		return nil, err
	}

	return ccm.Open(nil, nonce, ciphertext, additionalData)
}
