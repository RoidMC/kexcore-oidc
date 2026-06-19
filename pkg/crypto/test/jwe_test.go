// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/roidmc/kexcore-oidc/v2/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/v2/pkg/crypto/gm"
)

func TestSM2EncryptDecryptJWE_RoundTrip(t *testing.T) {
	privateKey, err := gm.SM2GenerateKey()
	if err != nil {
		t.Fatalf("SM2GenerateKey failed: %v", err)
	}

	plaintext := []byte("test message for SM2 JWE encryption")

	compact, err := crypto.SM2EncryptJWE(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2EncryptJWE failed: %v", err)
	}
	if compact == "" {
		t.Fatal("JWE compact serialization is empty")
	}

	decrypted, err := crypto.SM2DecryptJWE(privateKey, compact)
	if err != nil {
		t.Fatalf("SM2DecryptJWE failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match plaintext\ngot: %s\nwant: %s", decrypted, plaintext)
	}
}

func TestSM2EncryptDecryptJWE_CompactFormat(t *testing.T) {
	privateKey, _ := gm.SM2GenerateKey()
	plaintext := []byte("format validation")

	compact, err := crypto.SM2EncryptJWE(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2EncryptJWE failed: %v", err)
	}

	// Must have exactly 5 base64url parts
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("JWE compact serialization must have 5 parts, got %d", len(parts))
	}

	// Each part must be valid base64url
	for i, part := range parts {
		if part == "" {
			t.Errorf("part %d is empty", i)
		}
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			t.Errorf("part %d is not valid base64url: %v", i, err)
		}
	}

	// Verify JWE protected header contains correct algorithm identifiers
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to parse header: %v", err)
	}

	if header.Alg != crypto.SGD_SM2_3 {
		t.Errorf("expected alg=%s, got %s", crypto.SGD_SM2_3, header.Alg)
	}
	if header.Enc != crypto.SGD_SM4_GCM {
		t.Errorf("expected enc=%s, got %s", crypto.SGD_SM4_GCM, header.Enc)
	}
}

func TestSM2EncryptDecryptJWE_EmptyPayload(t *testing.T) {
	privateKey, _ := gm.SM2GenerateKey()
	plaintext := []byte{}

	compact, err := crypto.SM2EncryptJWE(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2EncryptJWE failed: %v", err)
	}

	decrypted, err := crypto.SM2DecryptJWE(privateKey, compact)
	if err != nil {
		t.Fatalf("SM2DecryptJWE failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestSM2EncryptDecryptJWE_Randomness(t *testing.T) {
	privateKey, _ := gm.SM2GenerateKey()
	plaintext := []byte("randomness test")

	compacts := make(map[string]bool)
	for i := 0; i < 5; i++ {
		compact, err := crypto.SM2EncryptJWE(&privateKey.PublicKey, plaintext)
		if err != nil {
			t.Fatalf("SM2EncryptJWE failed: %v", err)
		}
		if compacts[compact] {
			t.Error("identical JWE produced for same input - randomness check failed")
		}
		compacts[compact] = true

		decrypted, err := crypto.SM2DecryptJWE(privateKey, compact)
		if err != nil {
			t.Fatalf("SM2DecryptJWE failed: %v", err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Error("decryption mismatch in randomness test")
		}
	}
}

func TestSM2DecryptJWE_InvalidCompact(t *testing.T) {
	privateKey, _ := gm.SM2GenerateKey()

	tests := []struct {
		name    string
		compact string
	}{
		{"too few parts", "a.b.c"},
		{"too many parts", "a.b.c.d.e.f"},
		{"empty string", ""},
		{"malformed base64", "!!!.!!!.!!!.!!!.!!!"},
		{"single dot", "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.SM2DecryptJWE(privateKey, tt.compact)
			if err == nil {
				t.Error("expected error for invalid compact JWE")
			}
		})
	}
}

func TestSM2DecryptJWE_WrongKey(t *testing.T) {
	privateKey1, _ := gm.SM2GenerateKey()
	privateKey2, _ := gm.SM2GenerateKey()
	plaintext := []byte("wrong key test")

	compact, err := crypto.SM2EncryptJWE(&privateKey1.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2EncryptJWE failed: %v", err)
	}

	_, err = crypto.SM2DecryptJWE(privateKey2, compact)
	if err == nil {
		t.Error("expected decryption failure with wrong private key")
	}
}

func TestSM2DecryptJWE_TamperedCiphertext(t *testing.T) {
	privateKey, _ := gm.SM2GenerateKey()
	plaintext := []byte("tamper test")

	compact, err := crypto.SM2EncryptJWE(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2EncryptJWE failed: %v", err)
	}

	parts := strings.Split(compact, ".")
	origPart3 := parts[3]
	if len(origPart3) > 0 {
		b := []byte(origPart3)
		b[len(b)-1] ^= 0xff
		parts[3] = string(b)
	}

	tampered := strings.Join(parts, ".")
	_, err = crypto.SM2DecryptJWE(privateKey, tampered)
	if err == nil {
		t.Error("expected decryption failure for tampered ciphertext")
	}
}

func TestSM2EncryptDecryptJWE_LargePayload(t *testing.T) {
	privateKey, _ := gm.SM2GenerateKey()
	plaintext := make([]byte, 1024*10)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	compact, err := crypto.SM2EncryptJWE(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2EncryptJWE failed: %v", err)
	}

	decrypted, err := crypto.SM2DecryptJWE(privateKey, compact)
	if err != nil {
		t.Fatalf("SM2DecryptJWE failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("decrypted large payload doesn't match plaintext")
	}
}

func TestSM2EncryptDecryptJWE_UnicodePayload(t *testing.T) {
	privateKey, _ := gm.SM2GenerateKey()
	plaintext := []byte("你好，世界！国密 SM2/SM4 JWE 加解密测试")

	compact, err := crypto.SM2EncryptJWE(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2EncryptJWE failed: %v", err)
	}

	decrypted, err := crypto.SM2DecryptJWE(privateKey, compact)
	if err != nil {
		t.Fatalf("SM2DecryptJWE failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted unicode text doesn't match\ngot: %s\nwant: %s", decrypted, plaintext)
	}
}

// --- SM9 JWE tests ---

func TestSM9EncryptDecryptJWE_GCM(t *testing.T) {
	masterKey, err := gm.SM9GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("SM9GenerateEncryptMasterKey failed: %v", err)
	}

	uid := []byte("testuser@example.com")
	userKey, err := gm.SM9GenerateEncryptUserKey(masterKey, uid)
	if err != nil {
		t.Fatalf("SM9GenerateEncryptUserKey failed: %v", err)
	}

	plaintext := []byte("SM9 JWE encryption test with GCM")

	compact, err := crypto.SM9EncryptJWE(masterKey.PublicKey(), uid, crypto.SGD_SM4_GCM, plaintext)
	if err != nil {
		t.Fatalf("SM9EncryptJWE GCM failed: %v", err)
	}

	decrypted, err := crypto.SM9DecryptJWE(userKey, uid, compact)
	if err != nil {
		t.Fatalf("SM9DecryptJWE GCM failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match\ngot: %s\nwant: %s", decrypted, plaintext)
	}
}

func TestSM9EncryptDecryptJWE_CCM(t *testing.T) {
	masterKey, err := gm.SM9GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("SM9GenerateEncryptMasterKey failed: %v", err)
	}

	uid := []byte("testuser@example.com")
	userKey, err := gm.SM9GenerateEncryptUserKey(masterKey, uid)
	if err != nil {
		t.Fatalf("SM9GenerateEncryptUserKey failed: %v", err)
	}

	plaintext := []byte("SM9 JWE encryption test with CCM")

	compact, err := crypto.SM9EncryptJWE(masterKey.PublicKey(), uid, crypto.SGD_SM4_CCM, plaintext)
	if err != nil {
		t.Fatalf("SM9EncryptJWE CCM failed: %v", err)
	}

	decrypted, err := crypto.SM9DecryptJWE(userKey, uid, compact)
	if err != nil {
		t.Fatalf("SM9DecryptJWE CCM failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match\ngot: %s\nwant: %s", decrypted, plaintext)
	}
}

func TestSM9EncryptDecryptJWE_DefaultEnc(t *testing.T) {
	masterKey, _ := gm.SM9GenerateEncryptMasterKey()
	uid := []byte("defaultuser")
	userKey, _ := gm.SM9GenerateEncryptUserKey(masterKey, uid)

	plaintext := []byte("default enc test")

	// Empty enc should default to SGD_SM4_GCM
	compact, err := crypto.SM9EncryptJWE(masterKey.PublicKey(), uid, "", plaintext)
	if err != nil {
		t.Fatalf("SM9EncryptJWE with empty enc failed: %v", err)
	}

	// Verify header enc field
	parts := strings.Split(compact, ".")
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}
	json.Unmarshal(headerJSON, &header)

	if header.Alg != crypto.SGD_SM9_3 {
		t.Errorf("expected alg=%s, got %s", crypto.SGD_SM9_3, header.Alg)
	}
	if header.Enc != crypto.SGD_SM4_GCM {
		t.Errorf("expected enc=%s (default), got %s", crypto.SGD_SM4_GCM, header.Enc)
	}

	decrypted, err := crypto.SM9DecryptJWE(userKey, uid, compact)
	if err != nil {
		t.Fatalf("SM9DecryptJWE failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("decrypted text doesn't match")
	}
}

func TestSM9EncryptDecryptJWE_WrongUID(t *testing.T) {
	masterKey, _ := gm.SM9GenerateEncryptMasterKey()
	uid := []byte("alice@example.com")
	wrongUID := []byte("bob@example.com")
	userKey, _ := gm.SM9GenerateEncryptUserKey(masterKey, uid)

	plaintext := []byte("wrong uid test")

	compact, err := crypto.SM9EncryptJWE(masterKey.PublicKey(), uid, crypto.SGD_SM4_GCM, plaintext)
	if err != nil {
		t.Fatalf("SM9EncryptJWE failed: %v", err)
	}

	// Decrypt with wrong UID should fail
	_, err = crypto.SM9DecryptJWE(userKey, wrongUID, compact)
	if err == nil {
		t.Error("expected decryption failure with wrong UID")
	}
}

func TestSM9EncryptDecryptJWE_CompactFormat(t *testing.T) {
	masterKey, _ := gm.SM9GenerateEncryptMasterKey()
	uid := []byte("formatuser")

	compact, err := crypto.SM9EncryptJWE(masterKey.PublicKey(), uid, crypto.SGD_SM4_CCM, []byte("format test"))
	if err != nil {
		t.Fatalf("SM9EncryptJWE failed: %v", err)
	}

	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("JWE must have 5 parts, got %d", len(parts))
	}

	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}
	json.Unmarshal(headerJSON, &header)

	if header.Alg != crypto.SGD_SM9_3 {
		t.Errorf("expected alg=%s, got %s", crypto.SGD_SM9_3, header.Alg)
	}
	if header.Enc != crypto.SGD_SM4_CCM {
		t.Errorf("expected enc=%s, got %s", crypto.SGD_SM4_CCM, header.Enc)
	}
}

func TestSM9EncryptDecryptJWE_EmptyPayload(t *testing.T) {
	masterKey, _ := gm.SM9GenerateEncryptMasterKey()
	uid := []byte("emptyuser")
	userKey, _ := gm.SM9GenerateEncryptUserKey(masterKey, uid)

	compact, err := crypto.SM9EncryptJWE(masterKey.PublicKey(), uid, crypto.SGD_SM4_GCM, []byte{})
	if err != nil {
		t.Fatalf("SM9EncryptJWE failed: %v", err)
	}

	decrypted, err := crypto.SM9DecryptJWE(userKey, uid, compact)
	if err != nil {
		t.Fatalf("SM9DecryptJWE failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

// --- AES-GCM helpers tests ---

func TestAESGCMEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}
	plaintext := []byte("AES-GCM round-trip test for OIDC JWE")
	aad := []byte("additional authenticated data")

	sealed, err := crypto.AESGCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatal("sealed output is empty")
	}

	decrypted, err := crypto.AESGCMDecrypt(key, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("AESGCMDecrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match\ngot: %s\nwant: %s", decrypted, plaintext)
	}
}

func TestAESGCMEncryptDecrypt_AES128(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 200)
	}
	plaintext := []byte("AES-128-GCM test")

	sealed, err := crypto.AESGCMEncrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("AESGCMEncrypt (AES-128) failed: %v", err)
	}

	decrypted, err := crypto.AESGCMDecrypt(key, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("AESGCMDecrypt (AES-128) failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("AES-128 round-trip mismatch")
	}
}

func TestAESGCMDecrypt_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(i + 1)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 50)
	}
	plaintext := []byte("wrong key test")

	sealed, err := crypto.AESGCMEncrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}

	_, err = crypto.AESGCMDecrypt(wrongKey, nonce, sealed, nil)
	if err == nil {
		t.Error("expected decryption failure with wrong key")
	}
}

func TestAESGCMDecrypt_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 50)
	}
	plaintext := []byte("tamper test")

	sealed, err := crypto.AESGCMEncrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}

	sealed[len(sealed)-1] ^= 0xff

	_, err = crypto.AESGCMDecrypt(key, nonce, sealed, nil)
	if err == nil {
		t.Error("expected decryption failure for tampered ciphertext")
	}
}

func TestAESGCMEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)

	sealed, err := crypto.AESGCMEncrypt(key, nonce, []byte{}, nil)
	if err != nil {
		t.Fatalf("AESGCMEncrypt empty plaintext failed: %v", err)
	}

	decrypted, err := crypto.AESGCMDecrypt(key, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("AESGCMDecrypt empty plaintext failed: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestAESGCMEncryptDecrypt_LargePayload(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 1024*10)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	sealed, err := crypto.AESGCMEncrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("AESGCMEncrypt large payload failed: %v", err)
	}

	decrypted, err := crypto.AESGCMDecrypt(key, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("AESGCMDecrypt large payload failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("large payload round-trip mismatch")
	}
}

func TestAESGCMEncrypt_InvalidKeyLength(t *testing.T) {
	key := make([]byte, 15) // Invalid: less than 16 bytes
	nonce := make([]byte, 12)
	_, err := crypto.AESGCMEncrypt(key, nonce, []byte("test"), nil)
	if err == nil {
		t.Error("expected error for invalid AES key length (15 bytes)")
	}
}

// --- SM9 unsupported enc tests ---

func TestSM9EncryptJWE_UnsupportedEnc(t *testing.T) {
	masterKey, _ := gm.SM9GenerateEncryptMasterKey()
	uid := []byte("unsupporteduser")

	_, err := crypto.SM9EncryptJWE(masterKey.PublicKey(), uid, "UNKNOWN_ENC", []byte("test"))
	if err == nil {
		t.Error("expected error for unsupported enc algorithm")
	}
}

func TestSM9DecryptJWE_UnsupportedEnc(t *testing.T) {
	masterKey, _ := gm.SM9GenerateEncryptMasterKey()
	uid := []byte("unsupporteduser")
	userKey, _ := gm.SM9GenerateEncryptUserKey(masterKey, uid)

	// Craft a JWE with unsupported enc
	header := struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}{Alg: crypto.SGD_SM9_3, Enc: "UNKNOWN_ENC"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	fakeKey := base64.RawURLEncoding.EncodeToString([]byte("fakekey"))
	fakeIV := base64.RawURLEncoding.EncodeToString(make([]byte, 12))
	fakeCipher := base64.RawURLEncoding.EncodeToString([]byte("cipher"))
	fakeTag := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	compact := headerB64 + "." + fakeKey + "." + fakeIV + "." + fakeCipher + "." + fakeTag

	_, err := crypto.SM9DecryptJWE(userKey, uid, compact)
	if err == nil {
		t.Error("expected error for unsupported enc during decryption")
	}
}

// --- SM2 header mismatch tests ---

func TestSM2DecryptJWE_HeaderMismatch(t *testing.T) {
	privateKey, _ := gm.SM2GenerateKey()

	// Craft a JWE with wrong alg header
	header := struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}{Alg: crypto.SGD_SM9_3, Enc: crypto.SGD_SM4_GCM}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	fakeKey := base64.RawURLEncoding.EncodeToString([]byte("fakekey"))
	fakeIV := base64.RawURLEncoding.EncodeToString(make([]byte, 12))
	fakeCipher := base64.RawURLEncoding.EncodeToString([]byte("cipher"))
	fakeTag := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	compact := headerB64 + "." + fakeKey + "." + fakeIV + "." + fakeCipher + "." + fakeTag

	_, err := crypto.SM2DecryptJWE(privateKey, compact)
	if err == nil {
		t.Error("expected error for SM2 header alg mismatch")
	}
}

func TestSM9DecryptJWE_HeaderMismatch(t *testing.T) {
	masterKey, _ := gm.SM9GenerateEncryptMasterKey()
	uid := []byte("mismatchuser")
	userKey, _ := gm.SM9GenerateEncryptUserKey(masterKey, uid)

	// Craft a JWE with wrong alg header
	header := struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}{Alg: crypto.SGD_SM2_3, Enc: crypto.SGD_SM4_GCM}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	fakeKey := base64.RawURLEncoding.EncodeToString([]byte("fakekey"))
	fakeIV := base64.RawURLEncoding.EncodeToString(make([]byte, 12))
	fakeCipher := base64.RawURLEncoding.EncodeToString([]byte("cipher"))
	fakeTag := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	compact := headerB64 + "." + fakeKey + "." + fakeIV + "." + fakeCipher + "." + fakeTag

	_, err := crypto.SM9DecryptJWE(userKey, uid, compact)
	if err == nil {
		t.Error("expected error for SM9 header alg mismatch")
	}
}

// --- ParseJWECompact tests ---

func TestParseJWECompact_Valid(t *testing.T) {
	privateKey, _ := gm.SM2GenerateKey()
	compact, _ := crypto.SM2EncryptJWE(&privateKey.PublicKey, []byte("parse test"))

	parts, header, err := crypto.ParseJWECompact(compact)
	if err != nil {
		t.Fatalf("ParseJWECompact failed: %v", err)
	}
	if len(parts) != 5 {
		t.Errorf("expected 5 parts, got %d", len(parts))
	}
	if header.Algorithm != crypto.SGD_SM2_3 {
		t.Errorf("expected alg=%s, got %s", crypto.SGD_SM2_3, header.Algorithm)
	}
	if header.Encryption != crypto.SGD_SM4_GCM {
		t.Errorf("expected enc=%s, got %s", crypto.SGD_SM4_GCM, header.Encryption)
	}
}

func TestParseJWECompact_TooFewParts(t *testing.T) {
	_, _, err := crypto.ParseJWECompact("a.b.c")
	if err == nil {
		t.Error("expected error for too few parts")
	}
}

func TestParseJWECompact_TooManyParts(t *testing.T) {
	_, _, err := crypto.ParseJWECompact("a.b.c.d.e.f")
	if err == nil {
		t.Error("expected error for too many parts")
	}
}

func TestParseJWECompact_EmptyString(t *testing.T) {
	_, _, err := crypto.ParseJWECompact("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestParseJWECompact_EmptyPart(t *testing.T) {
	_, _, err := crypto.ParseJWECompact("a.b..d.e")
	if err == nil {
		t.Error("expected error for empty part")
	}
}

func TestParseJWECompact_InvalidBase64Header(t *testing.T) {
	_, _, err := crypto.ParseJWECompact("!!!.b.c.d.e")
	if err == nil {
		t.Error("expected error for invalid base64 header")
	}
}

func TestParseJWECompact_InvalidJSONHeader(t *testing.T) {
	badHeader := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	_, _, err := crypto.ParseJWECompact(badHeader + ".b.c.d.e")
	if err == nil {
		t.Error("expected error for invalid JSON header")
	}
}
