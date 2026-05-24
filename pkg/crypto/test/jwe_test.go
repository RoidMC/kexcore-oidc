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

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
)

func TestSM2EncryptDecryptJWE_RoundTrip(t *testing.T) {
	privateKey, err := crypto.SM2GenerateKey()
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
	privateKey, _ := crypto.SM2GenerateKey()
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
	privateKey, _ := crypto.SM2GenerateKey()
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
	privateKey, _ := crypto.SM2GenerateKey()
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
	privateKey, _ := crypto.SM2GenerateKey()

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
	privateKey1, _ := crypto.SM2GenerateKey()
	privateKey2, _ := crypto.SM2GenerateKey()
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
	privateKey, _ := crypto.SM2GenerateKey()
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
	privateKey, _ := crypto.SM2GenerateKey()
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
	privateKey, _ := crypto.SM2GenerateKey()
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
	masterKey, err := crypto.SM9GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("SM9GenerateEncryptMasterKey failed: %v", err)
	}

	uid := []byte("testuser@example.com")
	userKey, err := crypto.SM9GenerateEncryptUserKey(masterKey, uid)
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
	masterKey, err := crypto.SM9GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("SM9GenerateEncryptMasterKey failed: %v", err)
	}

	uid := []byte("testuser@example.com")
	userKey, err := crypto.SM9GenerateEncryptUserKey(masterKey, uid)
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
	masterKey, _ := crypto.SM9GenerateEncryptMasterKey()
	uid := []byte("defaultuser")
	userKey, _ := crypto.SM9GenerateEncryptUserKey(masterKey, uid)

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
	masterKey, _ := crypto.SM9GenerateEncryptMasterKey()
	uid := []byte("alice@example.com")
	wrongUID := []byte("bob@example.com")
	userKey, _ := crypto.SM9GenerateEncryptUserKey(masterKey, uid)

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
	masterKey, _ := crypto.SM9GenerateEncryptMasterKey()
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
	masterKey, _ := crypto.SM9GenerateEncryptMasterKey()
	uid := []byte("emptyuser")
	userKey, _ := crypto.SM9GenerateEncryptUserKey(masterKey, uid)

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
