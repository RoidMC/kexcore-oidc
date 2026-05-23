// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/v1/pkg/crypto"
)

func TestGetHashAlgorithm_KnownAlgorithms(t *testing.T) {
	tests := []struct {
		alg      string
		wantSize int
	}{
		{"RS256", 32},
		{"ES256", 32},
		{"PS256", 32},
		{"HS256", 32},
		{"RS384", 48},
		{"ES384", 48},
		{"PS384", 48},
		{"HS384", 48},
		{"RS512", 64},
		{"ES512", 64},
		{"PS512", 64},
		{"HS512", 64},
		{"EdDSA", 64},
		{crypto.SGD_SM3_SM2, 32}, // GM/T 0125.1: SM2+SM3 digital signature
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			h, err := crypto.GetHashAlgorithm(tt.alg)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSize, h.Size(), "unexpected hash size for %s", tt.alg)
		})
	}
}

func TestGetHashAlgorithm_Unsupported(t *testing.T) {
	_, err := crypto.GetHashAlgorithm("UnsupportedAlg")
	require.Error(t, err)
	assert.ErrorIs(t, err, crypto.ErrUnsupportedAlgorithm)
}

func TestHashString(t *testing.T) {
	h, err := crypto.GetHashAlgorithm(crypto.SGD_SM3_SM2)
	require.NoError(t, err)

	// Hashing the same string twice should yield the same result.
	s1 := crypto.HashString(h, "hello", false)
	h, _ = crypto.GetHashAlgorithm(crypto.SGD_SM3_SM2)
	s2 := crypto.HashString(h, "hello", false)
	assert.Equal(t, s1, s2)

	// firstHalf should return half the digest length.
	h, _ = crypto.GetHashAlgorithm(crypto.SGD_SM3_SM2)
	half := crypto.HashString(h, "hello", true)
	full := crypto.HashString(h, "hello", false)
	assert.Less(t, len(half), len(full))
}

func TestSGDSM3SM2Binding(t *testing.T) {
	// Verify that SGD_SM3_SM2 maps to SM3 (32-byte digest) as required by GM/T standards.
	h, err := crypto.GetHashAlgorithm(crypto.SGD_SM3_SM2)
	require.NoError(t, err)
	assert.Equal(t, 32, h.Size(), "SGD_SM3_SM2 must bind to SM3 which produces 256-bit (32-byte) digest")
}

func TestSGDSM3HMACNotInGetHashAlgorithm(t *testing.T) {
	// SGD_SM3_HMAC is a message authentication algorithm, not a signing algorithm.
	// It should NOT be supported by GetHashAlgorithm.
	_, err := crypto.GetHashAlgorithm(crypto.SGD_SM3_HMAC)
	require.Error(t, err, "SGD_SM3_HMAC should not be a valid signing algorithm")
	assert.ErrorIs(t, err, crypto.ErrUnsupportedAlgorithm)
}

func TestGMConstants(t *testing.T) {
	// Verify all GM/T 0125.1 algorithm identifier constants are defined.
	assert.Equal(t, "SGD_SM3_SM2", crypto.SGD_SM3_SM2)
	assert.Equal(t, "SGD_SM3_HMAC", crypto.SGD_SM3_HMAC)
	assert.Equal(t, "SGD_SM2_3", crypto.SGD_SM2_3)
	assert.Equal(t, "SGD_SM9_3", crypto.SGD_SM9_3)
	assert.Equal(t, "SGD_SM4_CCM", crypto.SGD_SM4_CCM)
	assert.Equal(t, "SGD_SM4_GCM", crypto.SGD_SM4_GCM)
}

func TestHashString_NilHash(t *testing.T) {
	// When hash is nil, the original string should be returned unchanged.
	result := crypto.HashString(nil, "unchanged", false)
	assert.Equal(t, "unchanged", result)
}
