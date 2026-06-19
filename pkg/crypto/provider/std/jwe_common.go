// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package std

import (
	"encoding/base64"
	"fmt"

	"github.com/roidmc/kexcore-oidc/v2/pkg/crypto/util"
)

const (
	sgdSM2_3      = "SGD_SM2_3"
	sgdSM9_3      = "SGD_SM9_3"
	sgdSM4_GCM    = "SGD_SM4_GCM"
	sgdSM4_CCM    = "SGD_SM4_CCM"
	sm4GCMTagSize = 16
	sm4CCMTagSize = 16
)

func decryptJWEContent(cek []byte, enc string, parts []string) ([]byte, error) {
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode IV: %w", util.ErrInvalidJWECompact, err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode ciphertext: %w", util.ErrInvalidJWECompact, err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode tag: %w", util.ErrInvalidJWECompact, err)
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
		return nil, fmt.Errorf("%w: %s", util.ErrJWEUnsupportedEnc, enc)
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
