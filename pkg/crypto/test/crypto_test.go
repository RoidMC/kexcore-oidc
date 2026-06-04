// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/crypto/gm"
)

func TestEncryptAESRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	keyStr := string(key)

	plaintext := "hello world, AES GCM round trip test"
	encrypted, err := crypto.EncryptAES(plaintext, keyStr)
	if err != nil {
		t.Fatalf("EncryptAES failed: %v", err)
	}

	decrypted, err := crypto.DecryptAES(encrypted, keyStr)
	if err != nil {
		t.Fatalf("DecryptAES failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("round trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptAESOutputIsBase64(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	keyStr := string(key)

	encrypted, err := crypto.EncryptAES("test", keyStr)
	if err != nil {
		t.Fatalf("EncryptAES failed: %v", err)
	}

	_, err = base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		t.Errorf("EncryptAES output is not valid base64 URL encoding: %v", err)
	}
}

func TestDecryptAESInvalidInput(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	keyStr := string(key)

	_, err := crypto.DecryptAES("!!!not-valid-base64!!!", keyStr)
	if err == nil {
		t.Error("DecryptAES should fail on invalid base64 input")
	}
}

func TestDecryptAESWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	encrypted, err := crypto.EncryptAES("test", string(key1))
	if err != nil {
		t.Fatalf("EncryptAES failed: %v", err)
	}

	_, err = crypto.DecryptAES(encrypted, string(key2))
	if err == nil {
		t.Error("DecryptAES should fail with wrong key")
	}
}

func TestEncryptAESEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	keyStr := string(key)

	encrypted, err := crypto.EncryptAES("", keyStr)
	if err != nil {
		t.Fatalf("EncryptAES failed with empty plaintext: %v", err)
	}

	decrypted, err := crypto.DecryptAES(encrypted, keyStr)
	if err != nil {
		t.Fatalf("DecryptAES failed with empty ciphertext: %v", err)
	}

	if decrypted != "" {
		t.Errorf("expected empty string, got %q", decrypted)
	}
}

func TestDecryptAESShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	keyStr := string(key)

	short := base64.RawURLEncoding.EncodeToString([]byte{0x01})
	_, err := crypto.DecryptAES(short, keyStr)
	if err != crypto.ErrCipherTextTooShort {
		t.Errorf("expected ErrCipherTextTooShort, got %v", err)
	}
}

func TestEncryptAESTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	keyStr := string(key)

	encrypted, err := crypto.EncryptAES("sensitive data", keyStr)
	if err != nil {
		t.Fatalf("EncryptAES failed: %v", err)
	}

	raw, _ := base64.RawURLEncoding.DecodeString(encrypted)
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	_, err = crypto.DecryptAES(tampered, keyStr)
	if err == nil {
		t.Error("DecryptAES should fail on tampered ciphertext (GCM auth tag)")
	}
}

func TestEncryptSM4RoundTrip(t *testing.T) {
	key, err := gm.SM4GenerateKey()
	if err != nil {
		t.Fatalf("SM4GenerateKey failed: %v", err)
	}
	keyStr := string(key)

	plaintext := "hello world, SM4 GCM round trip test"
	encrypted, err := crypto.EncryptSM4(plaintext, keyStr)
	if err != nil {
		t.Fatalf("EncryptSM4 failed: %v", err)
	}

	decrypted, err := crypto.DecryptSM4(encrypted, keyStr)
	if err != nil {
		t.Fatalf("DecryptSM4 failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("round trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptSM4OutputIsBase64(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	keyStr := string(key)

	encrypted, err := crypto.EncryptSM4("test", keyStr)
	if err != nil {
		t.Fatalf("EncryptSM4 failed: %v", err)
	}

	_, err = base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		t.Errorf("EncryptSM4 output is not valid base64 URL encoding: %v", err)
	}
}

func TestDecryptSM4InvalidInput(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	keyStr := string(key)

	_, err := crypto.DecryptSM4("!!!not-valid-base64!!!", keyStr)
	if err == nil {
		t.Error("DecryptSM4 should fail on invalid base64 input")
	}
}

func TestDecryptSM4WrongKey(t *testing.T) {
	key1, _ := gm.SM4GenerateKey()
	key2, _ := gm.SM4GenerateKey()

	encrypted, err := crypto.EncryptSM4("test", string(key1))
	if err != nil {
		t.Fatalf("EncryptSM4 failed: %v", err)
	}

	_, err = crypto.DecryptSM4(encrypted, string(key2))
	if err == nil {
		t.Error("DecryptSM4 should fail with wrong key")
	}
}

func TestEncryptSM4EmptyPlaintext(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	keyStr := string(key)

	encrypted, err := crypto.EncryptSM4("", keyStr)
	if err != nil {
		t.Fatalf("EncryptSM4 failed with empty plaintext: %v", err)
	}

	decrypted, err := crypto.DecryptSM4(encrypted, keyStr)
	if err != nil {
		t.Fatalf("DecryptSM4 failed with empty ciphertext: %v", err)
	}

	if decrypted != "" {
		t.Errorf("expected empty string, got %q", decrypted)
	}
}

func TestEncryptSM4TamperedCiphertext(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	keyStr := string(key)

	encrypted, err := crypto.EncryptSM4("sensitive data", keyStr)
	if err != nil {
		t.Fatalf("EncryptSM4 failed: %v", err)
	}

	raw, _ := base64.RawURLEncoding.DecodeString(encrypted)
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	_, err = crypto.DecryptSM4(tampered, keyStr)
	if err == nil {
		t.Error("DecryptSM4 should fail on tampered ciphertext (GCM auth tag)")
	}
}
