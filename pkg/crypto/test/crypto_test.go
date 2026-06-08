// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"bytes"
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

// --- Edge Cases ---

func TestDecryptSM4ShortCiphertext(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	keyStr := string(key)

	short := base64.RawURLEncoding.EncodeToString([]byte{0x01})
	_, err := crypto.DecryptSM4(short, keyStr)
	if err != crypto.ErrCipherTextTooShort {
		t.Errorf("expected ErrCipherTextTooShort, got %v", err)
	}
}

func TestEncryptAESInvalidKeySize(t *testing.T) {
	_, err := crypto.EncryptAES("test", "short")
	if err == nil {
		t.Error("EncryptAES should fail with invalid key size")
	}
}

func TestEncryptSM4InvalidKeySize(t *testing.T) {
	_, err := crypto.EncryptSM4("test", "short")
	if err == nil {
		t.Error("EncryptSM4 should fail with invalid key size")
	}
}

// --- A192GCM tests ---

func TestEncryptA192GCMRoundTrip(t *testing.T) {
	key := make([]byte, 24)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plaintext := []byte("A192GCM round trip test")

	sealed, err := crypto.AESGCMEncrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("AESGCMEncrypt A192 failed: %v", err)
	}

	decrypted, err := crypto.AESGCMDecrypt(key, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("AESGCMDecrypt A192 failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("round trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// --- A128CBC-HS256 tests ---

func TestAESCBCEncryptDecrypt_A128CBC_HS256(t *testing.T) {
	key := make([]byte, 32) // 16 MAC + 16 ENC
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("A128CBC-HS256 round trip test")
	aad := []byte("additional authenticated data")

	sealed, err := crypto.AESCBCEncrypt("A128CBC-HS256", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("AESCBCEncrypt failed: %v", err)
	}

	decrypted, err := crypto.AESCBCDecrypt("A128CBC-HS256", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("AESCBCDecrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("round trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESCBCEncryptDecrypt_A192CBC_HS384(t *testing.T) {
	key := make([]byte, 48) // 24 MAC + 24 ENC
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("A192CBC-HS384 round trip test")
	aad := []byte("additional authenticated data")

	sealed, err := crypto.AESCBCEncrypt("A192CBC-HS384", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("AESCBCEncrypt failed: %v", err)
	}

	decrypted, err := crypto.AESCBCDecrypt("A192CBC-HS384", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("AESCBCDecrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("round trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESCBCEncryptDecrypt_A256CBC_HS512(t *testing.T) {
	key := make([]byte, 64) // 32 MAC + 32 ENC
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("A256CBC-HS512 round trip test")
	aad := []byte("additional authenticated data")

	sealed, err := crypto.AESCBCEncrypt("A256CBC-HS512", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("AESCBCEncrypt failed: %v", err)
	}

	decrypted, err := crypto.AESCBCDecrypt("A256CBC-HS512", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("AESCBCDecrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("round trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESCBCEncrypt_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	aad := []byte("test aad")

	sealed, err := crypto.AESCBCEncrypt("A128CBC-HS256", key, iv, []byte{}, aad)
	if err != nil {
		t.Fatalf("AESCBCEncrypt empty plaintext failed: %v", err)
	}

	decrypted, err := crypto.AESCBCDecrypt("A128CBC-HS256", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("AESCBCDecrypt empty plaintext failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestAESCBCEncrypt_LargePayload(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := make([]byte, 1024*10)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	aad := []byte("large payload aad")

	sealed, err := crypto.AESCBCEncrypt("A128CBC-HS256", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("AESCBCEncrypt large payload failed: %v", err)
	}

	decrypted, err := crypto.AESCBCDecrypt("A128CBC-HS256", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("AESCBCDecrypt large payload failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large payload round-trip mismatch")
	}
}

func TestAESCBCEncrypt_UnicodePayload(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("你好，世界！AES-CBC-HS 加解密测试")
	aad := []byte("unicode aad")

	sealed, err := crypto.AESCBCEncrypt("A128CBC-HS256", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("AESCBCEncrypt unicode failed: %v", err)
	}

	decrypted, err := crypto.AESCBCDecrypt("A128CBC-HS256", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("AESCBCDecrypt unicode failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("unicode round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESCBCDecrypt_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("wrong key test")
	aad := []byte("aad")

	sealed, err := crypto.AESCBCEncrypt("A128CBC-HS256", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("AESCBCEncrypt failed: %v", err)
	}

	_, err = crypto.AESCBCDecrypt("A128CBC-HS256", wrongKey, iv, sealed, aad)
	if err == nil {
		t.Error("AESCBCDecrypt should fail with wrong key")
	}
}

func TestAESCBCDecrypt_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("tamper test")
	aad := []byte("aad")

	sealed, err := crypto.AESCBCEncrypt("A128CBC-HS256", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("AESCBCEncrypt failed: %v", err)
	}

	// Tamper with ciphertext
	sealed[0] ^= 0xFF

	_, err = crypto.AESCBCDecrypt("A128CBC-HS256", key, iv, sealed, aad)
	if err == nil {
		t.Error("AESCBCDecrypt should fail on tampered ciphertext")
	}
}

func TestAESCBCDecrypt_WrongAAD(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("wrong aad test")
	aad := []byte("correct aad")
	wrongAAD := []byte("wrong aad")

	sealed, err := crypto.AESCBCEncrypt("A128CBC-HS256", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("AESCBCEncrypt failed: %v", err)
	}

	_, err = crypto.AESCBCDecrypt("A128CBC-HS256", key, iv, sealed, wrongAAD)
	if err == nil {
		t.Error("AESCBCDecrypt should fail with wrong AAD")
	}
}

func TestAESCBCEncrypt_InvalidKeyLength(t *testing.T) {
	key := make([]byte, 16) // Too short for A128CBC-HS256 (needs 32)
	iv := make([]byte, 16)
	_, err := crypto.AESCBCEncrypt("A128CBC-HS256", key, iv, []byte("test"), nil)
	if err == nil {
		t.Error("AESCBCEncrypt should fail with invalid key length")
	}
}

func TestAESCBCEncrypt_InvalidIVLength(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12) // Should be 16 for CBC
	_, err := crypto.AESCBCEncrypt("A128CBC-HS256", key, iv, []byte("test"), nil)
	if err == nil {
		t.Error("AESCBCEncrypt should fail with invalid IV length")
	}
}

func TestAESCBCEncrypt_UnsupportedEnc(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	_, err := crypto.AESCBCEncrypt("UNKNOWN", key, iv, []byte("test"), nil)
	if err == nil {
		t.Error("AESCBCEncrypt should fail with unsupported enc")
	}
}

// --- DispatchContent* tests ---

func TestDispatchContentEncrypt_A128GCM(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	iv := make([]byte, 12)
	rand.Read(iv)
	plaintext := []byte("DispatchContent A128GCM test")
	aad := []byte("aad")

	sealed, err := crypto.DispatchContentEncrypt("A128GCM", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("DispatchContentEncrypt failed: %v", err)
	}

	decrypted, err := crypto.DispatchContentDecrypt("A128GCM", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("DispatchContentDecrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("DispatchContent A128GCM round-trip mismatch")
	}
}

func TestDispatchContentEncrypt_A192GCM(t *testing.T) {
	key := make([]byte, 24)
	rand.Read(key)
	iv := make([]byte, 12)
	rand.Read(iv)
	plaintext := []byte("DispatchContent A192GCM test")
	aad := []byte("aad")

	sealed, err := crypto.DispatchContentEncrypt("A192GCM", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("DispatchContentEncrypt failed: %v", err)
	}

	decrypted, err := crypto.DispatchContentDecrypt("A192GCM", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("DispatchContentDecrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("DispatchContent A192GCM round-trip mismatch")
	}
}

func TestDispatchContentEncrypt_A256GCM(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 12)
	rand.Read(iv)
	plaintext := []byte("DispatchContent A256GCM test")
	aad := []byte("aad")

	sealed, err := crypto.DispatchContentEncrypt("A256GCM", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("DispatchContentEncrypt failed: %v", err)
	}

	decrypted, err := crypto.DispatchContentDecrypt("A256GCM", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("DispatchContentDecrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("DispatchContent A256GCM round-trip mismatch")
	}
}

func TestDispatchContentEncrypt_SM4GCM(t *testing.T) {
	key, _ := gm.SM4GenerateKey()
	iv := make([]byte, 12)
	rand.Read(iv)
	plaintext := []byte("DispatchContent SM4GCM test")
	aad := []byte("aad")

	sealed, err := crypto.DispatchContentEncrypt("SGD_SM4_GCM", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("DispatchContentEncrypt failed: %v", err)
	}

	decrypted, err := crypto.DispatchContentDecrypt("SGD_SM4_GCM", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("DispatchContentDecrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("DispatchContent SM4GCM round-trip mismatch")
	}
}

func TestDispatchContentEncrypt_A128CBC_HS256(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("DispatchContent A128CBC-HS256 test")
	aad := []byte("aad")

	sealed, err := crypto.DispatchContentEncrypt("A128CBC-HS256", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("DispatchContentEncrypt failed: %v", err)
	}

	decrypted, err := crypto.DispatchContentDecrypt("A128CBC-HS256", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("DispatchContentDecrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("DispatchContent A128CBC-HS256 round-trip mismatch")
	}
}

func TestDispatchContentEncrypt_A192CBC_HS384(t *testing.T) {
	key := make([]byte, 48)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("DispatchContent A192CBC-HS384 test")
	aad := []byte("aad")

	sealed, err := crypto.DispatchContentEncrypt("A192CBC-HS384", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("DispatchContentEncrypt failed: %v", err)
	}

	decrypted, err := crypto.DispatchContentDecrypt("A192CBC-HS384", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("DispatchContentDecrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("DispatchContent A192CBC-HS384 round-trip mismatch")
	}
}

func TestDispatchContentEncrypt_A256CBC_HS512(t *testing.T) {
	key := make([]byte, 64)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("DispatchContent A256CBC-HS512 test")
	aad := []byte("aad")

	sealed, err := crypto.DispatchContentEncrypt("A256CBC-HS512", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("DispatchContentEncrypt failed: %v", err)
	}

	decrypted, err := crypto.DispatchContentDecrypt("A256CBC-HS512", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("DispatchContentDecrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("DispatchContent A256CBC-HS512 round-trip mismatch")
	}
}

func TestDispatchContentEncrypt_UnsupportedEnc(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	_, err := crypto.DispatchContentEncrypt("UNKNOWN_ENC", key, iv, []byte("test"), nil)
	if err == nil {
		t.Error("DispatchContentEncrypt should fail with unsupported enc")
	}
}
