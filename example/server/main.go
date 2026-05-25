// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/emmansun/gmsm/sm9"
	"github.com/roidmc/kexcore-oidc/example/server/config"
	"github.com/roidmc/kexcore-oidc/example/server/exampleop"
	"github.com/roidmc/kexcore-oidc/example/server/storage"
	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/op"
)

func getUserStore(cfg *config.Config) (storage.UserStore, error) {
	if cfg.Issuer == "" {
		cfg.Issuer = fmt.Sprintf("http://localhost:%s/", cfg.Port)
	}
	if cfg.UsersFile == "" {
		return storage.NewUserStore(cfg.Issuer), nil
	}
	return storage.StoreFromFile(cfg.UsersFile)
}

func main() {
	cfg := config.FromEnvVars(&config.Config{Port: "9998"})
	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)

	issuer := cfg.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%s/", cfg.Port)
	}

	storage.RegisterClients(
		storage.NativeClient("native", cfg.RedirectURI...),
		storage.WebClient("web", "secret", cfg.RedirectURI...),
		storage.WebClient("api", "secret", cfg.RedirectURI...),
		// OIDF Conformance Suite 测试客户端
		storage.WebClient("Test Client 1", "test-secret-1",
			"https://www.certification.openid.net/test/a/kexcore-test/callback",
		),
		storage.WebClient("Test Client 2", "test-secret-2",
			"https://www.certification.openid.net/test/a/kexcore-test/callback",
		),
		// JWE 加密演示客户端
		storage.EncryptedWebClient("web-dir-sm4", "secret", oidc.JWEAlgDir, oidc.JWEEncSM4GCM,
			cfg.RedirectURI...,
		),
		storage.EncryptedWebClient("web-sm2", "secret", oidc.JWEAlgSM23, oidc.JWEEncSM4GCM,
			cfg.RedirectURI...,
		),
		storage.EncryptedWebClient("web-sm9", "secret", oidc.JWEAlgSM93, oidc.JWEEncSM4GCM,
			cfg.RedirectURI...,
		),
	)

	// the OpenIDProvider interface needs a Storage interface handling various checks and state manipulations
	// this might be the layer for accessing your database
	// in this example it will be handled in-memory
	store, err := getUserStore(cfg)
	if err != nil {
		logger.Error("cannot create UserStore", "error", err)
		os.Exit(1)
	}

	stor := storage.NewStorageWithAlgorithms(store, cfg.SigningAlgorithms)
	router := exampleop.SetupServer(
		issuer,
		stor,
		logger,
		false,
		cfg.CryptoMethod,
		op.WithCrypto(newMyCrypto(sha256.Sum256([]byte("test")), cfg.CryptoMethod, logger)),
	)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}
	logger.Info("server listening, press ctrl+c to stop", "addr", issuer)
	if server.ListenAndServe() != http.ErrServerClosed {
		logger.Error("server terminated", "error", err)
		os.Exit(1)
	}
}

var _ op.Encrypter = &myCrypto{}
var _ op.Decrypter = &myCrypto{}
var _ op.TokenEncryptionKeyProvider = &myCrypto{}
var _ op.SM2TokenEncryptionPublicKeyProvider = &myCrypto{}
var _ op.SM9TokenEncryptionPublicKeyProvider = &myCrypto{}

// myCrypto demonstrates how to provide a custom implementation of op.Crypto
// that also supports JWE token encryption (ID token, Userinfo).
//
// Set CRYPTO_METHOD=sm4 to use SM4-GCM (国密) instead of AES-256-GCM for JWE.
// The key must be 32 bytes for AES-256 or 16 bytes for SM4.
type myCrypto struct {
	key          []byte
	method       string // "aes" or "sm4"
	logger       *slog.Logger
	sm2PubKey    *ecdsa.PublicKey
	sm9MasterPub *sm9.EncryptMasterPublicKey
	sm9EncUID    []byte
}

func newMyCrypto(key [32]byte, method string, l *slog.Logger) *myCrypto {
	mc := &myCrypto{
		key:    append([]byte(nil), key[:]...),
		method: method,
		logger: l,
	}

	// Generate SM2 encryption key for SGD_SM2_3 JWE key wrapping
	sm2Key, err := crypto.SM2GenerateKey()
	if err != nil {
		l.Error("failed to generate SM2 encryption key", "error", err)
	} else {
		mc.sm2PubKey = sm2Key.Public().(*ecdsa.PublicKey)
	}

	// Generate SM9 encryption master key for SGD_SM9_3 JWE key wrapping
	sm9MasterKey, err := crypto.SM9GenerateEncryptMasterKey()
	if err != nil {
		l.Error("failed to generate SM9 encryption master key", "error", err)
	} else {
		mc.sm9MasterPub = sm9MasterKey.PublicKey()
		mc.sm9EncUID = []byte("kexcore-jwe")
	}

	return mc
}

// TokenEncryptionKey returns the raw symmetric key for JWE "dir" mode encryption.
func (m *myCrypto) TokenEncryptionKey() []byte {
	return m.key
}

// Encrypt encrypts the payload using the underlying raw AES/SM4 cipher.
// For ID token JWE encryption, the OP uses TokenEncryptionKey() + oidc.EncryptToken*.
func (m *myCrypto) Encrypt(s string) (string, error) {
	m.logger.Info("encrypting", "method", m.method)
	if m.method == "sm4" {
		return crypto.EncryptSM4(s, string(m.key))
	}
	return crypto.EncryptAES(s, string(m.key))
}

// Decrypt decrypts the payload.
func (m *myCrypto) Decrypt(s string) (string, error) {
	m.logger.Info("decrypting", "method", m.method)
	if m.method == "sm4" {
		return crypto.DecryptSM4(s, string(m.key))
	}
	return crypto.DecryptAES(s, string(m.key))
}

// myJWEEnc returns the JWE content encryption algorithm string for this crypto method.
func (m *myCrypto) myJWEEnc() string {
	if m.method == "sm4" {
		return oidc.JWEEncSM4GCM
	}
	return oidc.JWEEncA256GCM
}

// SM2TokenEncryptionPublicKey returns the SM2 public key for SGD_SM2_3 JWE key wrapping.
func (m *myCrypto) SM2TokenEncryptionPublicKey() *ecdsa.PublicKey {
	return m.sm2PubKey
}

// SM9TokenEncryptionMasterPublicKey returns the SM9 master public key for SGD_SM9_3 JWE key wrapping.
func (m *myCrypto) SM9TokenEncryptionMasterPublicKey() *sm9.EncryptMasterPublicKey {
	return m.sm9MasterPub
}

// SM9TokenEncryptionUID returns the user identifier for SM9 encryption.
func (m *myCrypto) SM9TokenEncryptionUID() []byte {
	return m.sm9EncUID
}
