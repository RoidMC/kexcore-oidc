// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

// Package util provides shared JWE types and parsing functions used by both
// the crypto package (public API) and crypto/provider/std (implementations).
// This package has zero dependency on either, breaking what would otherwise
// be a circular import.
package util

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// JWE errors shared across crypto and provider/std.
var (
	ErrInvalidJWECompact = errors.New("kexcore/crypto: invalid JWE compact serialization")
	ErrInvalidJWEParts   = errors.New("kexcore/crypto: JWE compact serialization must have exactly 5 parts")
	ErrJWEKeyDecrypt     = errors.New("kexcore/crypto: failed to decrypt JWE encrypted key")
	ErrJWEContentDecrypt = errors.New("kexcore/crypto: failed to decrypt JWE content")
	ErrJWEHeaderMismatch = errors.New("kexcore/crypto: JWE header algorithm mismatch")
	ErrJWEUnsupportedEnc = errors.New("kexcore/crypto: unsupported JWE content encryption algorithm")
)

// JWEHeader represents the JOSE header for JWE.
type JWEHeader struct {
	Algorithm   string `json:"alg"`
	Encryption  string `json:"enc"`
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
}

// ParseJWECompact parses and validates a JWE compact serialization (5 dot-separated parts).
func ParseJWECompact(compact string) ([]string, *JWEHeader, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, nil, ErrInvalidJWEParts
	}
	for i, part := range parts {
		if i == 3 {
			continue
		}
		if part == "" {
			return nil, nil, fmt.Errorf("%w: part %d is empty", ErrInvalidJWECompact, i)
		}
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failed to decode header: %w", ErrInvalidJWECompact, err)
	}
	var header JWEHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, fmt.Errorf("%w: failed to parse header: %w", ErrInvalidJWECompact, err)
	}
	return parts, &header, nil
}
