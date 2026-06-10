// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

// Package std provides standard (international) JWE algorithm implementations
// backed by lestrrat-go/jwx. These are used as the software fallback when
// no HSM/KMS provider is registered in crypto.ProviderRegistry.
package std

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// EncryptJWEKW encrypts using AES Key Wrap or AES-GCM Key Wrap.
// Supported algorithms: A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, A256GCMKW.
func EncryptJWEKW(payload string, key []byte, alg, enc string) (string, error) {
	jk, err := jwk.Import[jwk.SymmetricKey](key)
	if err != nil {
		return "", fmt.Errorf("failed to create key: %w", err)
	}

	var kwAlg jwa.KeyEncryptionAlgorithm
	switch alg {
	case "A128KW":
		kwAlg = jwa.A128KW()
	case "A192KW":
		kwAlg = jwa.A192KW()
	case "A256KW":
		kwAlg = jwa.A256KW()
	case "A128GCMKW":
		kwAlg = jwa.A128GCMKW()
	case "A192GCMKW":
		kwAlg = jwa.A192GCMKW()
	case "A256GCMKW":
		kwAlg = jwa.A256GCMKW()
	default:
		return "", fmt.Errorf("unsupported key wrap algorithm: %s", alg)
	}

	encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(kwAlg, jk), jwe.WithContentEncryption(LookupJWEContentEnc(enc)))
	if err != nil {
		return "", fmt.Errorf("%s encryption failed: %w", alg, err)
	}
	return string(encrypted), nil
}

// DecryptJWEKW decrypts using AES Key Wrap or AES-GCM Key Wrap.
func DecryptJWEKW(compact string, key []byte, alg string) ([]byte, error) {
	jk, err := jwk.Import[jwk.SymmetricKey](key)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %w", err)
	}

	var kwAlg jwa.KeyEncryptionAlgorithm
	switch alg {
	case "A128KW":
		kwAlg = jwa.A128KW()
	case "A192KW":
		kwAlg = jwa.A192KW()
	case "A256KW":
		kwAlg = jwa.A256KW()
	case "A128GCMKW":
		kwAlg = jwa.A128GCMKW()
	case "A192GCMKW":
		kwAlg = jwa.A192GCMKW()
	case "A256GCMKW":
		kwAlg = jwa.A256GCMKW()
	default:
		return nil, fmt.Errorf("unsupported key wrap algorithm: %s", alg)
	}

	decrypted, err := jwe.Decrypt([]byte(compact), jwe.WithKey(kwAlg, jk))
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// EncryptJWERSAOAEP encrypts using RSA-OAEP key wrapping.
// key can be *rsa.PublicKey or jwk.Key.
func EncryptJWERSAOAEP(payload string, key interface{}, alg, enc string) (string, error) {
	var rsaAlg jwa.KeyEncryptionAlgorithm
	switch alg {
	case "RSA-OAEP":
		rsaAlg = jwa.RSA_OAEP()
	case "RSA-OAEP-256":
		rsaAlg = jwa.RSA_OAEP_256()
	case "RSA-OAEP-384":
		rsaAlg = jwa.RSA_OAEP_384()
	case "RSA-OAEP-512":
		rsaAlg = jwa.RSA_OAEP_512()
	default:
		return "", fmt.Errorf("unsupported RSA-OAEP algorithm: %s", alg)
	}

	if jk, ok := key.(jwk.Key); ok {
		encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(rsaAlg, jk), jwe.WithContentEncryption(LookupJWEContentEnc(enc)))
		if err != nil {
			return "", fmt.Errorf("%s encryption failed: %w", alg, err)
		}
		return string(encrypted), nil
	}

	pubKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("RSA-OAEP mode requires *rsa.PublicKey or jwk.Key, got %T", key)
	}
	encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(rsaAlg, pubKey), jwe.WithContentEncryption(LookupJWEContentEnc(enc)))
	if err != nil {
		return "", fmt.Errorf("%s encryption failed: %w", alg, err)
	}
	return string(encrypted), nil
}

// DecryptJWERSAOAEP decrypts using RSA-OAEP key wrapping.
func DecryptJWERSAOAEP(compact string, key interface{}) ([]byte, error) {
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

// EncryptJWEECDHES encrypts using ECDH-ES key agreement.
// key can be *ecdh.PublicKey or jwk.Key.
func EncryptJWEECDHES(payload string, key interface{}, alg, enc string) (string, error) {
	var ecdhesAlg jwa.KeyEncryptionAlgorithm
	switch alg {
	case "ECDH-ES":
		ecdhesAlg = jwa.ECDH_ES()
	case "ECDH-ES+A128KW":
		ecdhesAlg = jwa.ECDH_ES_A128KW()
	case "ECDH-ES+A192KW":
		ecdhesAlg = jwa.ECDH_ES_A192KW()
	case "ECDH-ES+A256KW":
		ecdhesAlg = jwa.ECDH_ES_A256KW()
	default:
		return "", fmt.Errorf("unsupported ECDH-ES algorithm: %s", alg)
	}

	if jk, ok := key.(jwk.Key); ok {
		encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(ecdhesAlg, jk), jwe.WithContentEncryption(LookupJWEContentEnc(enc)))
		if err != nil {
			return "", fmt.Errorf("%s encryption failed: %w", alg, err)
		}
		return string(encrypted), nil
	}

	var pubKey *ecdh.PublicKey
	switch k := key.(type) {
	case *ecdh.PublicKey:
		pubKey = k
	case *ecdsa.PublicKey:
		p, err := k.ECDH()
		if err != nil {
			return "", fmt.Errorf("failed to convert ecdsa.PublicKey to ecdh.PublicKey: %w", err)
		}
		pubKey = p
	default:
		return "", fmt.Errorf("ECDH-ES mode requires *ecdh.PublicKey, *ecdsa.PublicKey or jwk.Key, got %T", key)
	}
	encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(ecdhesAlg, pubKey), jwe.WithContentEncryption(LookupJWEContentEnc(enc)))
	if err != nil {
		return "", fmt.Errorf("%s encryption failed: %w", alg, err)
	}
	return string(encrypted), nil
}

// DecryptJWEECDHES decrypts using ECDH-ES key agreement.
func DecryptJWEECDHES(compact string, key interface{}) ([]byte, error) {
	var privKey *ecdh.PrivateKey
	switch k := key.(type) {
	case *ecdh.PrivateKey:
		privKey = k
	case *ecdsa.PrivateKey:
		p, err := k.ECDH()
		if err != nil {
			return nil, fmt.Errorf("failed to convert ecdsa.PrivateKey to ecdh.PrivateKey: %w", err)
		}
		privKey = p
	default:
		return nil, fmt.Errorf("ECDH-ES mode requires *ecdh.PrivateKey, *ecdsa.PrivateKey or jwk.Key, got %T", key)
	}
	decrypted, err := jwe.Decrypt([]byte(compact), jwe.WithKey(jwa.ECDH_ES(), privKey))
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// LookupJWEContentEnc maps enc string to jwa.ContentEncryptionAlgorithm.
func LookupJWEContentEnc(enc string) jwa.ContentEncryptionAlgorithm {
	switch enc {
	case "A128GCM":
		return jwa.A128GCM()
	case "A192GCM":
		return jwa.A192GCM()
	case "A256GCM":
		return jwa.A256GCM()
	case "A128CBC-HS256":
		return jwa.A128CBC_HS256()
	case "A192CBC-HS384":
		return jwa.A192CBC_HS384()
	case "A256CBC-HS512":
		return jwa.A256CBC_HS512()
	default:
		return jwa.A256GCM()
	}
}
