// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package config

import (
	"os"
	"strconv"
	"strings"
)

const (
	DefaultIssuerPort        = "9998"
	DefaultSigningAlgorithms = "RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512,EdDSA,HS256,HS384,HS512"
)

func lookupBool(name string, fallback bool) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

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
	// CryptoKey is hashed with SHA-256 to derive the 32-byte token encryption
	// key. The built-in default is for the example only; set CRYPTO_KEY in any
	// shared environment.
	CryptoKey   string
	TLSCertFile string
	TLSKeyFile  string
	// EnableSelfSignSSL uses the bundled self-signed certificate when no
	// TLS_CERT_FILE/TLS_KEY_FILE is provided. Defaults to true for the example.
	EnableSelfSignSSL bool
	// EnableSkipTLSCertVerify disables verification of TLS certificates for
	// outbound requests such as CIBA notifications. Defaults to false.
	// Only enable it in test setups.
	EnableSkipTLSCertVerify bool
	// EnableAutomatedCIBAApproval exposes POST /ciba/approve. Only for
	// automated OIDF conformance runs; keep it disabled elsewhere.
	EnableAutomatedCIBAApproval bool
}

func FromEnvVars(defaults *Config) *Config {
	if defaults == nil {
		defaults = &Config{}
	}
	cfg := &Config{
		Port:                    defaults.Port,
		RedirectURI:             defaults.RedirectURI,
		UsersFile:               defaults.UsersFile,
		SigningAlgorithms:       defaults.SigningAlgorithms,
		CryptoMethod:            defaults.CryptoMethod,
		CryptoKey:               defaults.CryptoKey,
		EnableSelfSignSSL:       true,
		EnableSkipTLSCertVerify: defaults.EnableSkipTLSCertVerify,
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
	if value, ok := os.LookupEnv("CRYPTO_KEY"); ok {
		cfg.CryptoKey = value
	}
	cfg.EnableSelfSignSSL = lookupBool("ENABLE_SELF_SIGN_SSL", cfg.EnableSelfSignSSL)
	cfg.EnableSkipTLSCertVerify = lookupBool("ENABLE_SKIP_TLS_CERT_VERIFY", cfg.EnableSkipTLSCertVerify)
	if value, ok := os.LookupEnv("TLS_CERT_FILE"); ok {
		cfg.TLSCertFile = value
	}
	if value, ok := os.LookupEnv("TLS_KEY_FILE"); ok {
		cfg.TLSKeyFile = value
	}
	if value, ok := os.LookupEnv("ENABLE_AUTOMATED_CIBA_APPROVAL"); ok {
		if enabled, err := strconv.ParseBool(value); err == nil {
			cfg.EnableAutomatedCIBAApproval = enabled
		}
	}
	// Auto-enable self-signed TLS if EnableSelfSignSSL is set and no cert/key provided
	if cfg.EnableSelfSignSSL && cfg.TLSCertFile == "" && cfg.TLSKeyFile == "" {
		cfg.TLSCertFile = "example/storm-server/cert/web/server.crt"
		cfg.TLSKeyFile = "example/storm-server/cert/web/server.key"
	}
	return cfg
}
