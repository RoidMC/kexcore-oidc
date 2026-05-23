// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/roidmc/kexcore-oidc/v1/pkg/crypto"
)

type Encrypter interface {
	Encrypt(string) (string, error)
}
type Decrypter interface {
	Decrypt(string) (string, error)
}

type Crypto interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

type aesCrypto struct {
	key string
}

func NewAESCrypto(key [32]byte) Crypto {
	return &aesCrypto{key: string(key[:32])}
}

func (c *aesCrypto) Encrypt(s string) (string, error) {
	return crypto.EncryptAES(s, c.key)
}

func (c *aesCrypto) Decrypt(s string) (string, error) {
	return crypto.DecryptAES(s, c.key)
}

type sm4Crypto struct {
	key string
}

func NewSM4Crypto(key [16]byte) Crypto {
	return &sm4Crypto{key: string(key[:])}
}

func (c *sm4Crypto) Encrypt(s string) (string, error) {
	return crypto.EncryptSM4(s, c.key)
}

func (c *sm4Crypto) Decrypt(s string) (string, error) {
	return crypto.DecryptSM4(s, c.key)
}

type aes256GCMCrypto struct {
	key   []byte
	keyId string
}

func NewAES256GCMCrypto(key [32]byte, keyId string) Crypto {
	return &aes256GCMCrypto{
		key:   key[:],
		keyId: keyId,
	}
}

func (c *aes256GCMCrypto) Encrypt(s string) (string, error) {
	jwkKey, err := jwk.Import[jwk.SymmetricKey](c.key)
	if err != nil {
		return "", fmt.Errorf("failed to import key: %w", err)
	}
	_ = jwkKey.Set(jwk.KeyIDKey, c.keyId)

	encrypted, err := jwe.Encrypt(
		[]byte(s),
		jwe.WithKey(jwa.A256GCMKW(), jwkKey),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	serialized := string(encrypted)
	return serialized, nil
}

func (c *aes256GCMCrypto) Decrypt(s string) (string, error) {
	decrypted, err := jwe.Decrypt(
		[]byte(s),
		jwe.WithKey(jwa.A256GCMKW(), c.key),
	)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	return string(decrypted), nil
}

type CompositeCrypto struct {
	encrypter Encrypter
	// decrypters is a list so that older encrypted values can still be decrypted.
	decrypters []Decrypter
}

func NewCompositeCrypto(encrypter Encrypter, decrypters []Decrypter) Crypto {
	return &CompositeCrypto{
		encrypter:  encrypter,
		decrypters: decrypters,
	}
}

func (cc CompositeCrypto) Encrypt(s string) (string, error) {
	return cc.encrypter.Encrypt(s)
}

func (cc CompositeCrypto) Decrypt(s string) (string, error) {
	for _, d := range cc.decrypters {
		decrypted, err := d.Decrypt(s)
		if err != nil {
			continue
		}
		return decrypted, nil
	}
	return "", errors.New("failed to decrypt value")
}
