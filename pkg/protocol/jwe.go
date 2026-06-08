// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package protocol

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
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
// All algorithms dispatch through the crypto ProviderRegistry for unified HSM/KMS support.
func EncryptTokenJWE(signedToken string, key interface{}, alg, enc string) (string, error) {
	switch alg {
	case JWEAlgSM23, JWEAlgSM93:
		return crypto.DispatchEncryptJWE([]byte(signedToken), key, alg)

	case JWEAlgDir:
		return encryptTokenDir(signedToken, key, enc)

	case JWEAlgA128GCMKW, JWEAlgA192GCMKW, JWEAlgA256GCMKW:
		return encryptGCMKW(signedToken, key, alg, enc)

	case JWEAlgA128KW, JWEAlgA192KW, JWEAlgA256KW:
		return encryptKW(signedToken, key, alg, enc)

	case JWEAlgRSAOAEP, JWEAlgRSAOAEP256, JWEAlgRSAOAEP384, JWEAlgRSAOAEP512:
		return encryptRSAOAEP(signedToken, key, alg, enc)

	case JWEAlgECDHES, JWEAlgECDHESA128KW, JWEAlgECDHESA192KW, JWEAlgECDHESA256KW:
		return encryptECDHES(signedToken, key, alg, enc)

	default:
		return "", fmt.Errorf("unsupported JWE key wrapping algorithm: %s", alg)
	}
}

// DecryptTokenJWE decrypts a JWE compact serialization.
// All algorithms dispatch through the crypto ProviderRegistry for unified HSM/KMS support.
func DecryptTokenJWE(compact string, key interface{}) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) == 3 {
		return []byte(compact), nil
	}
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWE header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("failed to parse JWE header: %w", err)
	}

	switch hdr.Alg {
	case JWEAlgSM23, JWEAlgSM93:
		return crypto.DispatchDecryptJWE(compact, key, hdr.Alg)

	case JWEAlgDir:
		symKey, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("dir mode requires []byte key, got %T", key)
		}
		return decryptDirMode(compact, symKey, hdr.Enc)

	case JWEAlgA128GCMKW, JWEAlgA192GCMKW, JWEAlgA256GCMKW:
		symKey, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%s mode requires []byte key, got %T", hdr.Alg, key)
		}
		return decryptGCMKW(compact, symKey)

	case JWEAlgA128KW, JWEAlgA192KW, JWEAlgA256KW:
		symKey, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%s mode requires []byte key, got %T", hdr.Alg, key)
		}
		return decryptKW(compact, symKey)

	case JWEAlgRSAOAEP, JWEAlgRSAOAEP256, JWEAlgRSAOAEP384, JWEAlgRSAOAEP512:
		return decryptRSAOAEP(compact, key)

	case JWEAlgECDHES, JWEAlgECDHESA128KW, JWEAlgECDHESA192KW, JWEAlgECDHESA256KW:
		return decryptECDHES(compact, key)

	default:
		return nil, fmt.Errorf("unsupported JWE algorithm: %s", hdr.Alg)
	}
}

// encryptTokenDir performs direct symmetric encryption (alg=dir) of a payload.
func encryptTokenDir(payload string, key interface{}, enc string) (string, error) {
	symKey, ok := key.([]byte)
	if !ok {
		return "", fmt.Errorf("dir mode requires []byte key, got %T", key)
	}

	header := map[string]string{"alg": "dir", "enc": enc}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	// Dispatch through registry for unified algorithm support
	provider, ok := crypto.DefaultRegistry.GetContentEncryptor(enc)
	if !ok {
		return "", fmt.Errorf("no content encrypt provider registered for: %s", enc)
	}
	sealed, err := provider.Encrypt(context.Background(), symKey, iv, []byte(payload), []byte(headerB64))
	if err != nil {
		return "", err
	}

	tagSize := 16
	if len(sealed) < tagSize {
		return "", errors.New("encryption output too short")
	}
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]
	return headerB64 + ".." +
		base64.RawURLEncoding.EncodeToString(iv) + "." +
		base64.RawURLEncoding.EncodeToString(ciphertext) + "." +
		base64.RawURLEncoding.EncodeToString(tag), nil
}

// decryptDirMode decrypts a JWE in dir mode.
func decryptDirMode(compact string, key []byte, enc string) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if parts[1] != "" {
		return nil, errors.New("expected empty encrypted key for dir mode")
	}
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("failed to decode tag: %w", err)
	}
	sealed := append(ciphertext, tag...)
	aad := []byte(parts[0])

	// Dispatch through registry for unified algorithm support
	provider, ok := crypto.DefaultRegistry.GetContentDecryptor(enc)
	if !ok {
		return nil, fmt.Errorf("no content decrypt provider registered for: %s", enc)
	}
	return provider.Decrypt(context.Background(), key, iv, sealed, aad)
}

// decryptGCMKW decrypts a JWE using AES-GCM key wrapping (A128GCMKW, A192GCMKW, A256GCMKW).
func decryptGCMKW(compact string, key []byte) ([]byte, error) {
	jk, err := jwk.Import[jwk.SymmetricKey](key)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %w", err)
	}
	decrypted, err := jwe.Decrypt([]byte(compact), jwe.WithKey(jwa.A256GCMKW(), jk))
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// encryptGCMKW encrypts using AES-GCM key wrapping.
func encryptGCMKW(signedToken string, key interface{}, alg, enc string) (string, error) {
	symKey, ok := key.([]byte)
	if !ok {
		return "", fmt.Errorf("%s mode requires []byte key, got %T", alg, key)
	}
	jk, err := jwk.Import[jwk.SymmetricKey](symKey)
	if err != nil {
		return "", fmt.Errorf("failed to create key: %w", err)
	}
	encAlg := jwa.A256GCMKW()
	switch alg {
	case JWEAlgA128GCMKW:
		encAlg = jwa.A128GCMKW()
	case JWEAlgA192GCMKW:
		encAlg = jwa.A192GCMKW()
	}
	encrypted, err := jwe.Encrypt([]byte(signedToken), jwe.WithKey(encAlg, jk), jwe.WithContentEncryption(lookupContentEnc(enc)))
	if err != nil {
		return "", fmt.Errorf("%s encryption failed: %w", alg, err)
	}
	return string(encrypted), nil
}

// decryptKW decrypts a JWE using AES Key Wrap (A128KW, A192KW, A256KW).
func decryptKW(compact string, key []byte) ([]byte, error) {
	jk, err := jwk.Import[jwk.SymmetricKey](key)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %w", err)
	}
	decrypted, err := jwe.Decrypt([]byte(compact), jwe.WithKey(jwa.A256KW(), jk))
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// encryptKW encrypts using AES Key Wrap.
func encryptKW(signedToken string, key interface{}, alg, enc string) (string, error) {
	symKey, ok := key.([]byte)
	if !ok {
		return "", fmt.Errorf("%s mode requires []byte key, got %T", alg, key)
	}
	jk, err := jwk.Import[jwk.SymmetricKey](symKey)
	if err != nil {
		return "", fmt.Errorf("failed to create key: %w", err)
	}
	kwAlg := jwa.A256KW()
	switch alg {
	case JWEAlgA128KW:
		kwAlg = jwa.A128KW()
	case JWEAlgA192KW:
		kwAlg = jwa.A192KW()
	}
	encrypted, err := jwe.Encrypt([]byte(signedToken), jwe.WithKey(kwAlg, jk), jwe.WithContentEncryption(lookupContentEnc(enc)))
	if err != nil {
		return "", fmt.Errorf("%s encryption failed: %w", alg, err)
	}
	return string(encrypted), nil
}

// decryptRSAOAEP decrypts a JWE using RSA-OAEP key wrapping.
func decryptRSAOAEP(compact string, key interface{}) ([]byte, error) {
	privKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA-OAEP mode requires *rsa.PrivateKey, got %T", key)
	}
	decrypted, err := jwe.Decrypt([]byte(compact), jwe.WithKey(jwa.RSA_OAEP(), privKey))
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// encryptRSAOAEP encrypts using RSA-OAEP key wrapping.
// key can be *rsa.PublicKey or jwk.Key (preferred, includes kid in JWE header).
func encryptRSAOAEP(signedToken string, key interface{}, alg, enc string) (string, error) {
	rsaAlg := jwa.RSA_OAEP()
	switch alg {
	case JWEAlgRSAOAEP256:
		rsaAlg = jwa.RSA_OAEP_256()
	case JWEAlgRSAOAEP384:
		rsaAlg = jwa.RSA_OAEP_384()
	case JWEAlgRSAOAEP512:
		rsaAlg = jwa.RSA_OAEP_512()
	}
	// Support both jwk.Key (with kid) and raw *rsa.PublicKey
	if jk, ok := key.(jwk.Key); ok {
		encrypted, err := jwe.Encrypt([]byte(signedToken), jwe.WithKey(rsaAlg, jk), jwe.WithContentEncryption(lookupContentEnc(enc)))
		if err != nil {
			return "", fmt.Errorf("%s encryption failed: %w", alg, err)
		}
		return string(encrypted), nil
	}
	pubKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("RSA-OAEP mode requires *rsa.PublicKey or jwk.Key, got %T", key)
	}
	encrypted, err := jwe.Encrypt([]byte(signedToken), jwe.WithKey(rsaAlg, pubKey), jwe.WithContentEncryption(lookupContentEnc(enc)))
	if err != nil {
		return "", fmt.Errorf("%s encryption failed: %w", alg, err)
	}
	return string(encrypted), nil
}

// decryptECDHES decrypts a JWE using ECDH-ES key agreement.
func decryptECDHES(compact string, key interface{}) ([]byte, error) {
	privKey, ok := key.(*ecdh.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ECDH-ES mode requires *ecdh.PrivateKey, got %T", key)
	}
	decrypted, err := jwe.Decrypt([]byte(compact), jwe.WithKey(jwa.ECDH_ES(), privKey))
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// encryptECDHES encrypts using ECDH-ES key agreement.
// key can be *ecdh.PublicKey or jwk.Key (preferred, includes kid in JWE header).
func encryptECDHES(signedToken string, key interface{}, alg, enc string) (string, error) {
	ecdhesAlg := jwa.ECDH_ES()
	switch alg {
	case JWEAlgECDHESA128KW:
		ecdhesAlg = jwa.ECDH_ES_A128KW()
	case JWEAlgECDHESA192KW:
		ecdhesAlg = jwa.ECDH_ES_A192KW()
	case JWEAlgECDHESA256KW:
		ecdhesAlg = jwa.ECDH_ES_A256KW()
	}
	// Support both jwk.Key (with kid) and raw *ecdh.PublicKey
	if jk, ok := key.(jwk.Key); ok {
		encrypted, err := jwe.Encrypt([]byte(signedToken), jwe.WithKey(ecdhesAlg, jk), jwe.WithContentEncryption(lookupContentEnc(enc)))
		if err != nil {
			return "", fmt.Errorf("%s encryption failed: %w", alg, err)
		}
		return string(encrypted), nil
	}
	pubKey, ok := key.(*ecdh.PublicKey)
	if !ok {
		return "", fmt.Errorf("ECDH-ES mode requires *ecdh.PublicKey or jwk.Key, got %T", key)
	}
	encrypted, err := jwe.Encrypt([]byte(signedToken), jwe.WithKey(ecdhesAlg, pubKey), jwe.WithContentEncryption(lookupContentEnc(enc)))
	if err != nil {
		return "", fmt.Errorf("%s encryption failed: %w", alg, err)
	}
	return string(encrypted), nil
}

// lookupContentEnc maps enc string to jwa.ContentEncryptionAlgorithm.
func lookupContentEnc(enc string) jwa.ContentEncryptionAlgorithm {
	switch enc {
	case JWEEncA128GCM:
		return jwa.A128GCM()
	case JWEEncA192GCM:
		return jwa.A192GCM()
	case JWEEncA256GCM:
		return jwa.A256GCM()
	case JWEEncA128CBC_HS256:
		return jwa.A128CBC_HS256()
	case JWEEncA192CBC_HS384:
		return jwa.A192CBC_HS384()
	case JWEEncA256CBC_HS512:
		return jwa.A256CBC_HS512()
	default:
		return jwa.A256GCM()
	}
}
