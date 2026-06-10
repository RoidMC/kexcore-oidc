// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package std

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	sgdSM2_3      = "SGD_SM2_3"
	sgdSM9_3      = "SGD_SM9_3"
	sgdSM4_GCM    = "SGD_SM4_GCM"
	sgdSM4_CCM    = "SGD_SM4_CCM"
	sm4GCMTagSize = 16
	sm4CCMTagSize = 16
)

var (
	errInvalidJWECompact = errors.New("kexcore/crypto: invalid JWE compact serialization")
	errInvalidJWEParts   = errors.New("kexcore/crypto: JWE compact serialization must have exactly 5 parts")
	errJWEKeyDecrypt     = errors.New("kexcore/crypto: failed to decrypt JWE encrypted key")
	errJWEContentDecrypt = errors.New("kexcore/crypto: failed to decrypt JWE content")
	errJWEHeaderMismatch = errors.New("kexcore/crypto: JWE header algorithm mismatch")
	errJWEUnsupportedEnc = errors.New("kexcore/crypto: unsupported JWE content encryption algorithm")
)

type jweHeader struct {
	Algorithm   string `json:"alg"`
	Encryption  string `json:"enc"`
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
}

func parseJWECompact(compact string) ([]string, *jweHeader, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, nil, errInvalidJWEParts
	}
	for i, part := range parts {
		if i == 3 {
			continue
		}
		if part == "" {
			return nil, nil, fmt.Errorf("%w: part %d is empty", errInvalidJWECompact, i)
		}
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failed to decode header: %w", errInvalidJWECompact, err)
	}
	var header jweHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, fmt.Errorf("%w: failed to parse header: %w", errInvalidJWECompact, err)
	}
	return parts, &header, nil
}

func decryptJWEContent(cek []byte, enc string, parts []string) ([]byte, error) {
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode IV: %w", errInvalidJWECompact, err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode ciphertext: %w", errInvalidJWECompact, err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode tag: %w", errInvalidJWECompact, err)
	}
	sealed := make([]byte, len(ciphertext)+len(tag))
	copy(sealed, ciphertext)
	copy(sealed[len(ciphertext):], tag)
	aad := []byte(parts[0])

	switch enc {
	case sgdSM4_GCM:
		return SM4GCMDecrypt(cek, iv, sealed, aad)
	case sgdSM4_CCM:
		return SM4CCMDecrypt(cek, iv, sealed, aad)
	default:
		return nil, fmt.Errorf("%w: %s", errJWEUnsupportedEnc, enc)
	}
}

func sm4TagSize(enc string) int {
	switch enc {
	case sgdSM4_GCM:
		return sm4GCMTagSize
	case sgdSM4_CCM:
		return sm4CCMTagSize
	default:
		return sm4GCMTagSize
	}
}
