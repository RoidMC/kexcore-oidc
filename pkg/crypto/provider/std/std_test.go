// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package std

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/roidmc/kexcore-oidc/v2/pkg/crypto/gm"
)

// --- Content encryption primitives ---

func TestAESGCMEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plaintext := []byte("AES-GCM round trip test")
	aad := []byte("additional data")

	sealed, err := AESGCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}
	decrypted, err := AESGCMDecrypt(key, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("AESGCMDecrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

func TestSM4GCMEncryptDecrypt(t *testing.T) {
	key, err := gm.SM4GenerateKey()
	if err != nil {
		t.Fatalf("SM4GenerateKey failed: %v", err)
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plaintext := []byte("SM4-GCM round trip test")
	aad := []byte("additional data")

	sealed, err := SM4GCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("SM4GCMEncrypt failed: %v", err)
	}
	decrypted, err := SM4GCMDecrypt(key, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("SM4GCMDecrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

func TestSM4CCMEncryptDecrypt(t *testing.T) {
	key, err := gm.SM4GenerateKey()
	if err != nil {
		t.Fatalf("SM4GenerateKey failed: %v", err)
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plaintext := []byte("SM4-CCM round trip test")
	aad := []byte("additional data")

	sealed, err := SM4CCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("SM4CCMEncrypt failed: %v", err)
	}
	decrypted, err := SM4CCMDecrypt(key, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("SM4CCMDecrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

func TestAESCBCEncryptDecrypt_A128CBC_HS256(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("AES-CBC round trip test")
	aad := []byte("aad")

	sealed, err := AESCBCEncrypt("A128CBC-HS256", key, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("AESCBCEncrypt failed: %v", err)
	}
	decrypted, err := AESCBCDecrypt("A128CBC-HS256", key, iv, sealed, aad)
	if err != nil {
		t.Fatalf("AESCBCDecrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

// --- SM2 JWE ---

func TestSM2JWERoundTrip(t *testing.T) {
	privateKey, err := gm.SM2GenerateKey()
	if err != nil {
		t.Fatalf("SM2GenerateKey failed: %v", err)
	}
	plaintext := []byte("SM2 JWE round trip test")

	compact, err := EncryptSM2JWE(plaintext, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("EncryptSM2JWE failed: %v", err)
	}
	decrypted, err := DecryptSM2JWE(compact, privateKey)
	if err != nil {
		t.Fatalf("DecryptSM2JWE failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

// --- SM9 JWE ---

func TestSM9JWERoundTrip_GCM(t *testing.T) {
	masterKey, err := gm.SM9GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("SM9GenerateEncryptMasterKey failed: %v", err)
	}
	uid := []byte("user@example.com")
	userKey, err := gm.SM9GenerateEncryptUserKey(masterKey, uid)
	if err != nil {
		t.Fatalf("SM9GenerateEncryptUserKey failed: %v", err)
	}
	plaintext := []byte("SM9 JWE GCM round trip test")

	compact, err := EncryptSM9JWE(plaintext, masterKey.PublicKey(), uid, sgdSM4_GCM)
	if err != nil {
		t.Fatalf("EncryptSM9JWE failed: %v", err)
	}
	decrypted, err := DecryptSM9JWE(compact, userKey, uid)
	if err != nil {
		t.Fatalf("DecryptSM9JWE failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

func TestSM9JWERoundTrip_CCM(t *testing.T) {
	masterKey, err := gm.SM9GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("SM9GenerateEncryptMasterKey failed: %v", err)
	}
	uid := []byte("user@example.com")
	userKey, err := gm.SM9GenerateEncryptUserKey(masterKey, uid)
	if err != nil {
		t.Fatalf("SM9GenerateEncryptUserKey failed: %v", err)
	}
	plaintext := []byte("SM9 JWE CCM round trip test")

	compact, err := EncryptSM9JWE(plaintext, masterKey.PublicKey(), uid, sgdSM4_CCM)
	if err != nil {
		t.Fatalf("EncryptSM9JWE failed: %v", err)
	}
	decrypted, err := DecryptSM9JWE(compact, userKey, uid)
	if err != nil {
		t.Fatalf("DecryptSM9JWE failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

// --- dir mode ---

func TestJWEDirRoundTrip_AESGCM(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("dir mode AES-GCM round trip test")

	compact, err := EncryptJWEDir(plaintext, key, "A256GCM")
	if err != nil {
		t.Fatalf("EncryptJWEDir failed: %v", err)
	}
	decrypted, err := DecryptJWEDir(compact, key, "A256GCM")
	if err != nil {
		t.Fatalf("DecryptJWEDir failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

func TestJWEDirRoundTrip_SM4GCM(t *testing.T) {
	key, err := gm.SM4GenerateKey()
	if err != nil {
		t.Fatalf("SM4GenerateKey failed: %v", err)
	}
	plaintext := []byte("dir mode SM4-GCM round trip test")

	compact, err := EncryptJWEDir(plaintext, key, sgdSM4_GCM)
	if err != nil {
		t.Fatalf("EncryptJWEDir failed: %v", err)
	}
	decrypted, err := DecryptJWEDir(compact, key, sgdSM4_GCM)
	if err != nil {
		t.Fatalf("DecryptJWEDir failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

// --- International JWE (KW) ---

func TestJWEKW_A128KW_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	payload := "A128KW round trip payload"

	compact, err := EncryptJWEKW(payload, key, "A128KW", "A128GCM")
	if err != nil {
		t.Fatalf("EncryptJWEKW failed: %v", err)
	}
	decrypted, err := DecryptJWEKW(compact, key, "A128KW")
	if err != nil {
		t.Fatalf("DecryptJWEKW failed: %v", err)
	}
	if string(decrypted) != payload {
		t.Errorf("round-trip mismatch")
	}
}

// --- International JWE (RSA-OAEP) ---

func TestJWERSAOAEP_RoundTrip(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	payload := "RSA-OAEP round trip payload"

	compact, err := EncryptJWERSAOAEP(payload, &privKey.PublicKey, "RSA-OAEP", "A256GCM")
	if err != nil {
		t.Fatalf("EncryptJWERSAOAEP failed: %v", err)
	}
	decrypted, err := DecryptJWERSAOAEP(compact, privKey)
	if err != nil {
		t.Fatalf("DecryptJWERSAOAEP failed: %v", err)
	}
	if string(decrypted) != payload {
		t.Errorf("round-trip mismatch")
	}
}

// --- International JWE (ECDH-ES) ---

func TestJWEECDHES_RoundTrip(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	payload := "ECDH-ES round trip payload"

	compact, err := EncryptJWEECDHES(payload, &privKey.PublicKey, "ECDH-ES", "A128GCM")
	if err != nil {
		t.Fatalf("EncryptJWEECDHES failed: %v", err)
	}
	decrypted, err := DecryptJWEECDHES(compact, privKey)
	if err != nil {
		t.Fatalf("DecryptJWEECDHES failed: %v", err)
	}
	if string(decrypted) != payload {
		t.Errorf("round-trip mismatch")
	}
}
