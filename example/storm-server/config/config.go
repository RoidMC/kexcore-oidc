// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package config

import (
	"os"
	"strings"
)

const (
	EnableSelfSignSSL        = "true"
	EnableSkipTLSCertVerify  = "true"
	DefaultIssuerPort        = "9998"
	DefaultSigningAlgorithms = "RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512,EdDSA,HS256,HS384,HS512"
)

func DefaultSigningAlgorithmsSlice() []string {
	return strings.Split(DefaultSigningAlgorithms, ",")
}

type Config struct {
	Port              string
	RedirectURI       []string
	UsersFile         string
	Issuer            string
	SigningAlgorithms []string
	CryptoMethod      string
	TLSCertFile       string
	TLSKeyFile        string
}

func FromEnvVars(defaults *Config) *Config {
	if defaults == nil {
		defaults = &Config{}
	}
	cfg := &Config{
		Port:              defaults.Port,
		RedirectURI:       defaults.RedirectURI,
		UsersFile:         defaults.UsersFile,
		SigningAlgorithms: defaults.SigningAlgorithms,
		CryptoMethod:      defaults.CryptoMethod,
	}
	if value, ok := os.LookupEnv("PORT"); ok {
		cfg.Port = value
	}
	if value, ok := os.LookupEnv("USERS_FILE"); ok {
		cfg.UsersFile = value
	}
	if value, ok := os.LookupEnv("REDIRECT_URI"); ok {
		cfg.RedirectURI = strings.Split(value, ",")
	}
	if value, ok := os.LookupEnv("ISSUER"); ok {
		cfg.Issuer = value
	}
	if value, ok := os.LookupEnv("SIGNING_ALGORITHMS"); ok {
		cfg.SigningAlgorithms = strings.Split(value, ",")
	} else if len(cfg.SigningAlgorithms) == 0 {
		cfg.SigningAlgorithms = strings.Split(DefaultSigningAlgorithms, ",")
	}
	if value, ok := os.LookupEnv("CRYPTO_METHOD"); ok {
		cfg.CryptoMethod = value
	} else if cfg.CryptoMethod == "" {
		cfg.CryptoMethod = "aes"
	}
	if value, ok := os.LookupEnv("TLS_CERT_FILE"); ok {
		cfg.TLSCertFile = value
	}
	if value, ok := os.LookupEnv("TLS_KEY_FILE"); ok {
		cfg.TLSKeyFile = value
	}
	// Auto-enable self-signed TLS if EnableSelfSignSSL is set and no cert/key provided
	if EnableSelfSignSSL == "true" && cfg.TLSCertFile == "" && cfg.TLSKeyFile == "" {
		cfg.TLSCertFile = "example/storm-server/cert/web/server.crt"
		cfg.TLSKeyFile = "example/storm-server/cert/web/server.key"
	}
	return cfg
}
