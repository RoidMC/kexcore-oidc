// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
)

func TestSM9GenerateEncryptMasterKey(t *testing.T) {
	masterKey, err := crypto.SM9GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("SM9GenerateEncryptMasterKey failed: %v", err)
	}
	if masterKey == nil {
		t.Fatal("master key is nil")
	}
}

func TestSM9GenerateSignMasterKey(t *testing.T) {
	masterKey, err := crypto.SM9GenerateSignMasterKey()
	if err != nil {
		t.Fatalf("SM9GenerateSignMasterKey failed: %v", err)
	}
	if masterKey == nil {
		t.Fatal("master key is nil")
	}
}

func TestSM9EncryptDecrypt(t *testing.T) {
	masterKey, err := crypto.SM9GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("SM9GenerateEncryptMasterKey failed: %v", err)
	}

	uid := []byte("alice@example.com")
	userKey, err := crypto.SM9GenerateEncryptUserKey(masterKey, uid)
	if err != nil {
		t.Fatalf("SM9GenerateEncryptUserKey failed: %v", err)
	}

	plaintext := []byte("SM9 encryption test message")

	ciphertext, err := crypto.SM9Encrypt(masterKey.PublicKey(), uid, plaintext)
	if err != nil {
		t.Fatalf("SM9Encrypt failed: %v", err)
	}

	decrypted, err := crypto.SM9Decrypt(userKey, uid, ciphertext)
	if err != nil {
		t.Fatalf("SM9Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match\ngot: %s\nwant: %s", decrypted, plaintext)
	}
}

func TestSM9EncryptDecrypt_WrongUID(t *testing.T) {
	masterKey, _ := crypto.SM9GenerateEncryptMasterKey()
	uid := []byte("alice@example.com")
	wrongUID := []byte("bob@example.com")
	userKey, _ := crypto.SM9GenerateEncryptUserKey(masterKey, uid)

	plaintext := []byte("wrong uid test")

	ciphertext, err := crypto.SM9Encrypt(masterKey.PublicKey(), uid, plaintext)
	if err != nil {
		t.Fatalf("SM9Encrypt failed: %v", err)
	}

	_, err = crypto.SM9Decrypt(userKey, wrongUID, ciphertext)
	if err == nil {
		t.Error("expected decryption failure with wrong UID")
	}
}

func TestSM9SignVerify(t *testing.T) {
	masterKey, err := crypto.SM9GenerateSignMasterKey()
	if err != nil {
		t.Fatalf("SM9GenerateSignMasterKey failed: %v", err)
	}

	uid := []byte("alice@example.com")
	userKey, err := crypto.SM9GenerateSignUserKey(masterKey, uid)
	if err != nil {
		t.Fatalf("SM9GenerateSignUserKey failed: %v", err)
	}

	hash := []byte("message to be signed")

	signature, err := crypto.SM9Sign(userKey, hash)
	if err != nil {
		t.Fatalf("SM9Sign failed: %v", err)
	}

	if !crypto.SM9Verify(masterKey.PublicKey(), uid, hash, signature) {
		t.Error("SM9 signature verification failed")
	}
}

func TestSM9SignVerify_WrongMessage(t *testing.T) {
	masterKey, _ := crypto.SM9GenerateSignMasterKey()
	uid := []byte("alice@example.com")
	userKey, _ := crypto.SM9GenerateSignUserKey(masterKey, uid)

	signature, _ := crypto.SM9Sign(userKey, []byte("correct message"))

	if crypto.SM9Verify(masterKey.PublicKey(), uid, []byte("wrong message"), signature) {
		t.Error("verification should fail for wrong message")
	}
}

func TestSM9SignVerify_WrongUID(t *testing.T) {
	masterKey, _ := crypto.SM9GenerateSignMasterKey()
	uid := []byte("alice@example.com")
	wrongUID := []byte("bob@example.com")
	userKey, _ := crypto.SM9GenerateSignUserKey(masterKey, uid)

	signature, _ := crypto.SM9Sign(userKey, []byte("test message"))

	if crypto.SM9Verify(masterKey.PublicKey(), wrongUID, []byte("test message"), signature) {
		t.Error("verification should fail for wrong UID")
	}
}

func TestSM9WrapUnwrapKey(t *testing.T) {
	masterKey, _ := crypto.SM9GenerateEncryptMasterKey()
	uid := []byte("alice@example.com")
	userKey, _ := crypto.SM9GenerateEncryptUserKey(masterKey, uid)

	keyLen := 16 // SM4 key size
	wrappedKey, cipherDER, err := crypto.SM9WrapKey(masterKey.PublicKey(), uid, keyLen)
	if err != nil {
		t.Fatalf("SM9WrapKey failed: %v", err)
	}
	if len(wrappedKey) != keyLen {
		t.Errorf("expected wrapped key length %d, got %d", keyLen, len(wrappedKey))
	}

	unwrappedKey, err := crypto.SM9UnwrapKey(userKey, uid, cipherDER, keyLen)
	if err != nil {
		t.Fatalf("SM9UnwrapKey failed: %v", err)
	}

	if !bytes.Equal(wrappedKey, unwrappedKey) {
		t.Errorf("unwrapped key doesn't match\ngot: %x\nwant: %x", unwrappedKey, wrappedKey)
	}
}
