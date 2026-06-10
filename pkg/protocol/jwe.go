// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package protocol

import (
	"context"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
)

// SM9EncryptKey is the protocol-layer interface for SM9 encryption keys.
// It hides the underlying gmsm type from protocol consumers.
// Implementations are provided by pkg/crypto (gmsm) or HSM adapters.
//
// The canonical implementation is crypto.SM9MasterPublicKey, which wraps
// *sm9.EncryptMasterPublicKey + UID. HSM/KMS vendors can implement this
// interface to provide their own SM9 key material.
type SM9EncryptKey interface {
	// MarshalBinary returns the SM9 master public key in its canonical byte representation.
	MarshalBinary() ([]byte, error)
	// GetUID returns the user identifier for SM9 identity-based encryption.
	GetUID() []byte
}

// JWEService is the unified entry point for JWE encryption and decryption.
// Both OP and RP can use it without caring about the underlying implementation.
type JWEService interface {
	// Encrypt encrypts plaintext using the specified JWE algorithms.
	// alg is the key wrapping algorithm (e.g. "dir", "SGD_SM2_3", "SGD_SM9_3").
	// enc is the content encryption algorithm (e.g. "A256GCM", "SGD_SM4_GCM").
	// key is the encryption key material; type depends on alg:
	//   - "dir": []byte symmetric key
	//   - "SGD_SM2_3": *ecdsa.PublicKey
	//   - "SGD_SM9_3": SM9EncryptKey
	Encrypt(ctx context.Context, plaintext []byte, key interface{}, alg, enc string) (string, error)

	// Decrypt decrypts a JWE compact serialization.
	// key is the decryption key material; type depends on the JWE header alg.
	Decrypt(ctx context.Context, token string, key interface{}) ([]byte, error)
}

// EncryptTokenJWE encrypts a signed JWT using the specified JWE algorithm.
// All algorithms dispatch through the crypto package for unified HSM/KMS support.
func EncryptTokenJWE(signedToken string, key interface{}, alg, enc string) (string, error) {
	return crypto.EncryptJWE([]byte(signedToken), key, alg, enc)
}

// DecryptTokenJWE decrypts a JWE compact serialization.
// All algorithms dispatch through the crypto package for unified HSM/KMS support.
func DecryptTokenJWE(compact string, key interface{}) ([]byte, error) {
	return crypto.DecryptJWE(compact, key)
}
