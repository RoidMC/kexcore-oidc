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
	// default port for the http server to run
	DefaultIssuerPort = "9998"

	// DefaultSigningAlgorithms is the default set of JWS signing algorithms.
	// RS256 is always included for OIDC spec compliance.
	DefaultSigningAlgorithms = "RS256,RS384,RS512,EdDSA,SGD_SM3_SM2"
)

type Config struct {
	Port              string
	RedirectURI       []string
	UsersFile         string
	Issuer            string
	SigningAlgorithms []string // JWS signing algorithms to enable (e.g. RS256, SGD_SM3_SM2)
	CryptoMethod      string   // token encryption method: "aes" (default) or "sm4"
}

// FromEnvVars loads configuration parameters from environment variables.
// If there is no such variable defined, then use default values.
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
	return cfg
}
