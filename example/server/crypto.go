package main

import (
	"log/slog"

	"github.com/roidmc/kexcore-oidc/v1/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/v1/pkg/op"
)

var _ op.Encrypter = &myCrypto{}
var _ op.Decrypter = &myCrypto{}

// myCrypto demonstrates how to provide your custom implementation of op.Crypto.
// Set CRYPTO_METHOD=sm4 to use SM4 (国密) instead of AES for token encryption.
type myCrypto struct {
	key    string
	method string // "aes" or "sm4"
	logger *slog.Logger
}

func newMyCrypto(key [32]byte, method string, l *slog.Logger) *myCrypto {
	return &myCrypto{
		key:    string(key[:32]),
		method: method,
		logger: l,
	}
}

func (m *myCrypto) Decrypt(s string) (string, error) {
	m.logger.Info("decrypting", "method", m.method)
	if m.method == "sm4" {
		return crypto.DecryptSM4(s, m.key)
	}
	return crypto.DecryptAES(s, m.key)
}

func (m *myCrypto) Encrypt(s string) (string, error) {
	m.logger.Info("encrypting", "method", m.method)
	if m.method == "sm4" {
		return crypto.EncryptSM4(s, m.key)
	}
	return crypto.EncryptAES(s, m.key)
}
