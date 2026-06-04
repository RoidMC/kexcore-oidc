// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/roidmc/kexcore-oidc/pkg/crypto/gm"
)

func TestSM4GenerateKey(t *testing.T) {
	key, err := gm.SM4GenerateKey()
	if err != nil {
		t.Fatalf("SM4GenerateKey failed: %v", err)
	}
	if len(key) != gm.SM4BlockSize {
		t.Errorf("expected key length %d, got %d", gm.SM4BlockSize, len(key))
	}

	key2, err := gm.SM4GenerateKey()
	if err != nil {
		t.Fatalf("SM4GenerateKey failed: %v", err)
	}
	if bytes.Equal(key, key2) {
		t.Error("generated keys should be different")
	}
}

func TestSM4NewCipher(t *testing.T) {
	key := make([]byte, gm.SM4BlockSize)
	_, err := gm.SM4NewCipher(key)
	if err != nil {
		t.Errorf("SM4NewCipher failed with valid key: %v", err)
	}

	invalidKey := make([]byte, 15)
	_, err = gm.SM4NewCipher(invalidKey)
	if err != gm.ErrInvalidSM4KeySize {
		t.Errorf("expected ErrInvalidSM4KeySize, got %v", err)
	}
}

func TestSM4ECB(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	plaintext := []byte("hello world, this is a test message for SM4 ECB mode")

	ciphertext, err := gm.SM4EncryptECB(key, plaintext)
	if err != nil {
		t.Fatalf("SM4EncryptECB failed: %v", err)
	}

	decrypted, err := gm.SM4DecryptECB(key, ciphertext)
	if err != nil {
		t.Fatalf("SM4DecryptECB failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match plaintext\ngot: %s\nwant: %s", decrypted, plaintext)
	}
}

func TestSM4CBC(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	plaintext := []byte("hello world, this is a test message for SM4 CBC mode")

	ciphertext, err := gm.SM4EncryptCBC(key, plaintext)
	if err != nil {
		t.Fatalf("SM4EncryptCBC failed: %v", err)
	}

	if len(ciphertext) <= gm.SM4BlockSize {
		t.Error("ciphertext should contain IV prepended")
	}

	decrypted, err := gm.SM4DecryptCBC(key, ciphertext)
	if err != nil {
		t.Fatalf("SM4DecryptCBC failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match plaintext\ngot: %s\nwant: %s", decrypted, plaintext)
	}
}

func TestSM4CBCWithIV(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	iv := make([]byte, gm.SM4BlockSize)
	plaintext := []byte("test with provided IV")

	ciphertext, err := gm.SM4EncryptCBCWithIV(key, iv, plaintext)
	if err != nil {
		t.Fatalf("SM4EncryptCBCWithIV failed: %v", err)
	}

	decrypted, err := gm.SM4DecryptCBCWithIV(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("SM4DecryptCBCWithIV failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match plaintext")
	}
}

func TestSM4GCM(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	plaintext := []byte("hello world, this is a test for GCM mode")
	additionalData := []byte("additional authenticated data")

	ciphertext, err := gm.SM4EncryptGCM(key, plaintext, additionalData)
	if err != nil {
		t.Fatalf("SM4EncryptGCM failed: %v", err)
	}

	if len(ciphertext) <= gm.SM4GCMNonceSize {
		t.Error("ciphertext should contain nonce prepended")
	}

	decrypted, err := gm.SM4DecryptGCM(key, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("SM4DecryptGCM failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match plaintext")
	}
}

func TestSM4GCMWithNonce(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	nonce := make([]byte, gm.SM4GCMNonceSize)
	plaintext := []byte("test with provided nonce")
	additionalData := []byte("aad")

	ciphertext, err := gm.SM4EncryptGCMWithNonce(key, nonce, plaintext, additionalData)
	if err != nil {
		t.Fatalf("SM4EncryptGCMWithNonce failed: %v", err)
	}

	decrypted, err := gm.SM4DecryptGCMWithNonce(key, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("SM4DecryptGCMWithNonce failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match plaintext")
	}
}

func TestSM4GCMTamperedCiphertext(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	plaintext := []byte("test message")

	ciphertext, err := gm.SM4EncryptGCM(key, plaintext, nil)
	if err != nil {
		t.Fatalf("SM4EncryptGCM failed: %v", err)
	}

	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = gm.SM4DecryptGCM(key, ciphertext, nil)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestSM4GCMWrongAdditionalData(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	plaintext := []byte("test message")
	additionalData := []byte("correct aad")

	ciphertext, err := gm.SM4EncryptGCM(key, plaintext, additionalData)
	if err != nil {
		t.Fatalf("SM4EncryptGCM failed: %v", err)
	}

	_, err = gm.SM4DecryptGCM(key, ciphertext, []byte("wrong aad"))
	if err == nil {
		t.Error("expected error for wrong additional data")
	}
}

func TestSM4InvalidPadding(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	plaintext := []byte("hello world 1234")
	ciphertext, err := gm.SM4EncryptECB(key, plaintext)
	if err != nil {
		t.Fatalf("SM4EncryptECB failed: %v", err)
	}

	for attempts := 0; attempts < 256; attempts++ {
		ciphertext[len(ciphertext)-1] ^= byte(attempts)
		_, err = gm.SM4DecryptECB(key, ciphertext)
		ciphertext[len(ciphertext)-1] ^= byte(attempts)
		if err != nil {
			return
		}
	}
	t.Error("expected error for invalid padding after 256 attempts")
}

func TestSM4KeyHexConversion(t *testing.T) {
	key, _ := gm.SM4GenerateKey()

	hexKey := gm.SM4KeyToHex(key)
	if len(hexKey) != gm.SM4BlockSize*2 {
		t.Errorf("expected hex key length %d, got %d", gm.SM4BlockSize*2, len(hexKey))
	}

	decodedKey, err := gm.SM4KeyFromHex(hexKey)
	if err != nil {
		t.Fatalf("SM4KeyFromHex failed: %v", err)
	}

	if !bytes.Equal(key, decodedKey) {
		t.Error("decoded key doesn't match original")
	}
}

func TestSM4EmptyPlaintext(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	plaintext := []byte{}

	ciphertext, err := gm.SM4EncryptCBC(key, plaintext)
	if err != nil {
		t.Fatalf("SM4EncryptCBC failed: %v", err)
	}

	decrypted, err := gm.SM4DecryptCBC(key, ciphertext)
	if err != nil {
		t.Fatalf("SM4DecryptCBC failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty decrypted, got %v", decrypted)
	}
}

func TestSM4InvalidKeySize(t *testing.T) {
	invalidKey := make([]byte, 15)
	plaintext := []byte("test")

	_, err := gm.SM4EncryptECB(invalidKey, plaintext)
	if err != gm.ErrInvalidSM4KeySize {
		t.Errorf("expected ErrInvalidSM4KeySize, got %v", err)
	}
}

func TestSM4InvalidIVSize(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	invalidIV := make([]byte, 15)
	plaintext := []byte("test")

	_, err := gm.SM4EncryptCBCWithIV(key, invalidIV, plaintext)
	if err != gm.ErrInvalidSM4IVSize {
		t.Errorf("expected ErrInvalidSM4IVSize, got %v", err)
	}
}

func TestSM4InvalidNonceSize(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	invalidNonce := make([]byte, 15)
	plaintext := []byte("test")

	_, err := gm.SM4EncryptGCMWithNonce(key, invalidNonce, plaintext, nil)
	if err != gm.ErrInvalidSM4NonceSize {
		t.Errorf("expected ErrInvalidSM4NonceSize, got %v", err)
	}
}

func TestSM4ShortCiphertext(t *testing.T) {
	key, _ := gm.SM4GenerateKey()

	shortCiphertext := make([]byte, gm.SM4BlockSize-1)
	_, err := gm.SM4DecryptCBC(key, shortCiphertext)
	if err == nil {
		t.Error("expected error for short ciphertext")
	}

	shortGCMCiphertext := make([]byte, gm.SM4GCMNonceSize-1)
	_, err = gm.SM4DecryptGCM(key, shortGCMCiphertext, nil)
	if err == nil {
		t.Error("expected error for short GCM ciphertext")
	}
}

// --- SM4-CCM tests ---

func TestSM4CCM(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	plaintext := []byte("hello world, this is a test for CCM mode")
	additionalData := []byte("additional authenticated data")

	ciphertext, err := gm.SM4EncryptCCM(key, plaintext, additionalData)
	if err != nil {
		t.Fatalf("SM4EncryptCCM failed: %v", err)
	}

	if len(ciphertext) <= gm.SM4CCMNonceSize {
		t.Error("ciphertext should contain nonce prepended")
	}

	decrypted, err := gm.SM4DecryptCCM(key, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("SM4DecryptCCM failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match plaintext")
	}
}

func TestSM4CCMWithNonce(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	nonce := make([]byte, gm.SM4CCMNonceSize)
	plaintext := []byte("test with provided nonce")
	additionalData := []byte("aad")

	ciphertext, err := gm.SM4EncryptCCMWithNonce(key, nonce, plaintext, additionalData)
	if err != nil {
		t.Fatalf("SM4EncryptCCMWithNonce failed: %v", err)
	}

	decrypted, err := gm.SM4DecryptCCMWithNonce(key, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("SM4DecryptCCMWithNonce failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match plaintext")
	}
}

func TestSM4CCMTamperedCiphertext(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	plaintext := []byte("test message for CCM tamper detection")

	ciphertext, err := gm.SM4EncryptCCM(key, plaintext, nil)
	if err != nil {
		t.Fatalf("SM4EncryptCCM failed: %v", err)
	}

	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = gm.SM4DecryptCCM(key, ciphertext, nil)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestSM4CCMWrongAdditionalData(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	plaintext := []byte("test message")
	additionalData := []byte("correct aad")

	ciphertext, err := gm.SM4EncryptCCM(key, plaintext, additionalData)
	if err != nil {
		t.Fatalf("SM4EncryptCCM failed: %v", err)
	}

	_, err = gm.SM4DecryptCCM(key, ciphertext, []byte("wrong aad"))
	if err == nil {
		t.Error("expected error for wrong additional data")
	}
}

func TestSM4CCMInvalidNonceSize(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	invalidNonce := make([]byte, 15)
	plaintext := []byte("test")

	_, err := gm.SM4EncryptCCMWithNonce(key, invalidNonce, plaintext, nil)
	if err == nil {
		t.Error("expected error for invalid nonce size")
	}
}

func TestSM4CCMShortCiphertext(t *testing.T) {
	key, _ := gm.SM4GenerateKey()

	shortCiphertext := make([]byte, gm.SM4CCMNonceSize-1)
	_, err := gm.SM4DecryptCCM(key, shortCiphertext, nil)
	if err == nil {
		t.Error("expected error for short CCM ciphertext")
	}
}
