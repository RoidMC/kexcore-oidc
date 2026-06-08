// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package gm

import (
	"crypto/rand"
	"errors"

	"github.com/emmansun/gmsm/sm9"
)

var (
	ErrInvalidSM9EncryptMasterPublicKey = errors.New("kexcore/crypto: sm9 invalid encrypt master public key")
	ErrInvalidSM9EncryptPrivateKey      = errors.New("kexcore/crypto: sm9 invalid encrypt private key")
	ErrInvalidSM9SignMasterPrivateKey   = errors.New("kexcore/crypto: sm9 invalid sign master private key")
	ErrInvalidSM9SignMasterPublicKey    = errors.New("kexcore/crypto: sm9 invalid sign master public key")
)

const (
	// SM9HIDSign is the system-defined hid value for SM9 digital signature per GB/T 41389-2022.
	SM9HIDSign byte = 0x01
	// SM9HIDEncrypt is the system-defined hid value for SM9 encryption per GB/T 41389-2022.
	SM9HIDEncrypt byte = 0x03
)

// SM9GenerateEncryptMasterKey generates an SM9 encryption master key pair.
func SM9GenerateEncryptMasterKey() (*sm9.EncryptMasterPrivateKey, error) {
	return sm9.GenerateEncryptMasterKey(rand.Reader)
}

// SM9GenerateSignMasterKey generates an SM9 signature master key pair.
func SM9GenerateSignMasterKey() (*sm9.SignMasterPrivateKey, error) {
	return sm9.GenerateSignMasterKey(rand.Reader)
}

// SM9GenerateEncryptUserKey generates an SM9 encryption user private key from the master key.
func SM9GenerateEncryptUserKey(masterKey *sm9.EncryptMasterPrivateKey, uid []byte) (*sm9.EncryptPrivateKey, error) {
	return masterKey.GenerateUserKey(uid, SM9HIDEncrypt)
}

// SM9GenerateSignUserKey generates an SM9 signature user private key from the master key.
func SM9GenerateSignUserKey(masterKey *sm9.SignMasterPrivateKey, uid []byte) (*sm9.SignPrivateKey, error) {
	return masterKey.GenerateUserKey(uid, SM9HIDSign)
}

// SM9WrapKey wraps a key of kLen bytes using SM9 encryption (SGD_SM9_3).
// Returns the wrapped key and the ASN.1-encoded encryption metadata.
func SM9WrapKey(masterPubKey *sm9.EncryptMasterPublicKey, uid []byte, kLen int) ([]byte, []byte, error) {
	return masterPubKey.WrapKey(rand.Reader, uid, SM9HIDEncrypt, kLen)
}

// SM9UnwrapKey unwraps an SM9-encrypted key using the user's encryption private key.
func SM9UnwrapKey(userKey *sm9.EncryptPrivateKey, uid []byte, cipherDER []byte, kLen int) ([]byte, error) {
	return userKey.UnwrapKey(uid, cipherDER, kLen)
}

// SM9Encrypt encrypts plaintext using SM9 public key encryption.
func SM9Encrypt(masterPubKey *sm9.EncryptMasterPublicKey, uid []byte, plaintext []byte) ([]byte, error) {
	return sm9.EncryptASN1(rand.Reader, masterPubKey, uid, SM9HIDEncrypt, plaintext, nil)
}

// SM9Decrypt decrypts SM9-encrypted ciphertext using the user's encryption private key.
func SM9Decrypt(userKey *sm9.EncryptPrivateKey, uid []byte, ciphertext []byte) ([]byte, error) {
	return sm9.DecryptASN1(userKey, uid, ciphertext)
}

// SM9Sign signs data using the SM9 signature user private key.
func SM9Sign(userKey *sm9.SignPrivateKey, hash []byte) ([]byte, error) {
	return sm9.SignASN1(rand.Reader, userKey, hash)
}

// SM9Verify verifies an SM9 signature using the master public key and user identifier.
func SM9Verify(masterPubKey *sm9.SignMasterPublicKey, uid []byte, hash, signature []byte) bool {
	return sm9.VerifyASN1(masterPubKey, uid, SM9HIDSign, hash, signature)
}
