// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op

import (
	"crypto/ecdsa"
	"crypto/rand"
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

// TokenEncryptionKeyProvider is an optional interface that Crypto implementations
// can adopt to expose their raw key material for JWE token encryption (ID token, Userinfo).
// The returned key byte slice must be 16 bytes for SM4/AES-128 or 32 bytes for AES-256.
type TokenEncryptionKeyProvider interface {
	TokenEncryptionKey() []byte
}

// SM2TokenEncryptionPublicKeyProvider is an optional interface for Crypto
// implementations that provide an SM2 public key for encrypting ID tokens
// using SGD_SM2_3 key wrapping per GM/T 0125.3.
type SM2TokenEncryptionPublicKeyProvider interface {
	SM2TokenEncryptionPublicKey() *ecdsa.PublicKey
}

// SM9TokenEncryptionPublicKeyProvider is an optional interface for Crypto
// implementations that provide an SM9 master public key and UID for encrypting
// ID tokens using SGD_SM9_3 key wrapping per GM/T 0125.3.
type SM9TokenEncryptionPublicKeyProvider interface {
	SM9TokenEncryptionKey() *crypto.SM9MasterPublicKey
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

func (c *aes256GCMCrypto) TokenEncryptionKey() []byte {
	return c.key
}

// sm4GCMCrypto implements JWE-based encryption using direct key mode (dir)
// with SM4-GCM content encryption (SGD_SM4_GCM) per GM/T 0125.3.
//
// Different from sm4Crypto which does raw SM4-GCM, this produces standard
// JWE compact serialization: header..iv.ciphertext.tag
// (encrypted key is empty because alg=dir).
type sm4GCMCrypto struct {
	key   []byte
	keyId string
}

// NewSM4GCMCrypto creates a Crypto that uses JWE with dir key management
// and SM4-GCM content encryption. The key must be 16 bytes (128 bits).
func NewSM4GCMCrypto(key [16]byte, keyId string) Crypto {
	return &sm4GCMCrypto{
		key:   append([]byte(nil), key[:]...),
		keyId: keyId,
	}
}

// jweSm4Header is the JOSE header for SM4-GCM JWE (dir mode).
type jweSm4Header struct {
	Algorithm  string `json:"alg"`
	Encryption string `json:"enc"`
	KeyID      string `json:"kid,omitempty"`
}

func (c *sm4GCMCrypto) Encrypt(s string) (string, error) {
	// 1. Build JWE protected header
	header := jweSm4Header{
		Algorithm:  "dir",
		Encryption: crypto.SGD_SM4_GCM,
		KeyID:      c.keyId,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWE header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// 2. Generate random IV (96 bits for GCM)
	iv := make([]byte, crypto.SM4GCMNonceSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	// 3. Encrypt with SM4-GCM using AAD = headerB64
	sealed, err := crypto.SM4EncryptGCMWithNonce(c.key, iv, []byte(s), []byte(headerB64))
	if err != nil {
		return "", fmt.Errorf("SM4-GCM encryption failed: %w", err)
	}

	// 4. Split ciphertext and tag (tag = 16 bytes)
	tagSize := crypto.SM4GCMTagSize
	if len(sealed) < tagSize {
		return "", errors.New("SM4-GCM output too short")
	}
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	// 5. Build JWE compact serialization: header..iv.ciphertext.tag
	return headerB64 + ".." +
		base64.RawURLEncoding.EncodeToString(iv) + "." +
		base64.RawURLEncoding.EncodeToString(ciphertext) + "." +
		base64.RawURLEncoding.EncodeToString(tag), nil
}

func (c *sm4GCMCrypto) Decrypt(s string) (string, error) {
	// 1. Parse JWE compact serialization
	parts := strings.Split(s, ".")
	if len(parts) != 5 {
		return "", fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWE header: %w", err)
	}

	var header jweSm4Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", fmt.Errorf("failed to parse JWE header: %w", err)
	}

	if header.Algorithm != "dir" {
		return "", fmt.Errorf("unsupported JWE alg: %s (expected dir)", header.Algorithm)
	}
	if header.Encryption != crypto.SGD_SM4_GCM {
		return "", fmt.Errorf("unsupported JWE enc: %s (expected %s)", header.Encryption, crypto.SGD_SM4_GCM)
	}

	// 2. Verify encrypted key is empty (dir mode)
	if parts[1] != "" {
		return "", errors.New("expected empty encrypted key for dir mode")
	}

	// 3. Decode IV, ciphertext, tag
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("failed to decode IV: %w", err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return "", fmt.Errorf("failed to decode tag: %w", err)
	}

	// 4. Reassemble sealed bytes (ciphertext || tag)
	sealed := make([]byte, len(ciphertext)+len(tag))
	copy(sealed, ciphertext)
	copy(sealed[len(ciphertext):], tag)

	// 5. Decrypt with SM4-GCM
	plaintext, err := crypto.SM4DecryptGCMWithNonce(c.key, iv, sealed, []byte(parts[0]))
	if err != nil {
		return "", fmt.Errorf("SM4-GCM decryption failed: %w", err)
	}

	return string(plaintext), nil
}

func (c *sm4GCMCrypto) TokenEncryptionKey() []byte {
	return c.key
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
