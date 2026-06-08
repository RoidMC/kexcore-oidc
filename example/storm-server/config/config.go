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
	DefaultIssuerPort        = "9998"
	DefaultSigningAlgorithms = "RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512,HS256,HS384,HS512,EdDSA"
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
	return cfg
}
