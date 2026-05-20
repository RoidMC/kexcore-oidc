// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/v1/pkg/crypto"
)

func TestGetHashAlgorithm_KnownAlgorithms(t *testing.T) {
	tests := []struct {
		alg      jose.SignatureAlgorithm
		wantSize int
	}{
		{jose.RS256, 32},
		{jose.ES256, 32},
		{jose.PS256, 32},
		{jose.RS384, 48},
		{jose.ES384, 48},
		{jose.PS384, 48},
		{jose.RS512, 64},
		{jose.ES512, 64},
		{jose.PS512, 64},
		{jose.EdDSA, 64},
		{crypto.SM2, 32}, // SM2-SM3 mode: SM3 produces 32-byte digest
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			h, err := crypto.GetHashAlgorithm(tt.alg)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSize, h.Size(), "unexpected hash size for %s", tt.alg)
		})
	}
}

func TestGetHashAlgorithm_Unsupported(t *testing.T) {
	_, err := crypto.GetHashAlgorithm(jose.HS256)
	require.Error(t, err)
	assert.ErrorIs(t, err, crypto.ErrUnsupportedAlgorithm)
}

func TestHashString(t *testing.T) {
	h, err := crypto.GetHashAlgorithm(crypto.SM2)
	require.NoError(t, err)

	// Hashing the same string twice should yield the same result.
	s1 := crypto.HashString(h, "hello", false)
	h, _ = crypto.GetHashAlgorithm(crypto.SM2)
	s2 := crypto.HashString(h, "hello", false)
	assert.Equal(t, s1, s2)

	// firstHalf should return half the digest length.
	h, _ = crypto.GetHashAlgorithm(crypto.SM2)
	half := crypto.HashString(h, "hello", true)
	full := crypto.HashString(h, "hello", false)
	assert.Less(t, len(half), len(full))
}

func TestSM2SM3Binding(t *testing.T) {
	// Verify that SM2 maps to SM3 (32-byte digest) as required by GM/T standards.
	h, err := crypto.GetHashAlgorithm(crypto.SM2)
	require.NoError(t, err)
	assert.Equal(t, 32, h.Size(), "SM2 must bind to SM3 which produces 256-bit (32-byte) digest")

	// Ensure SM2 signature algorithm is distinct from standard Jose algorithms.
	assert.Equal(t, jose.SignatureAlgorithm("SM2"), crypto.SM2)
}

func TestHashString_NilHash(t *testing.T) {
	// When hash is nil, the original string should be returned unchanged.
	result := crypto.HashString(nil, "unchanged", false)
	assert.Equal(t, "unchanged", result)
}
