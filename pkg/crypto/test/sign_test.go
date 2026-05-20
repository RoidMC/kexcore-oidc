// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/v1/pkg/crypto"
)

func newTestSigner(t *testing.T) (jose.Signer, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       privateKey,
	}, nil)
	require.NoError(t, err)

	return signer, privateKey
}

type testPayload struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

func TestSign_Ok(t *testing.T) {
	signer, privateKey := newTestSigner(t)
	payload := testPayload{
		Sub:   "user-1",
		Email: "user1@example.com",
	}

	jws, err := crypto.Sign(payload, signer)
	require.NoError(t, err)
	assert.NotEmpty(t, jws)

	parsed, err := jose.ParseSigned(jws, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	raw, err := parsed.Verify(&privateKey.PublicKey)
	require.NoError(t, err)

	var decoded testPayload
	err = json.Unmarshal(raw, &decoded)
	require.NoError(t, err)
	assert.Equal(t, payload.Sub, decoded.Sub)
	assert.Equal(t, payload.Email, decoded.Email)
}

func TestSignPayload_Ok(t *testing.T) {
	signer, privateKey := newTestSigner(t)
	payload := []byte(`{"sub":"user-2","email":"user2@example.com"}`)

	jws, err := crypto.SignPayload(payload, signer)
	require.NoError(t, err)
	assert.NotEmpty(t, jws)

	parsed, err := jose.ParseSigned(jws, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	raw, err := parsed.Verify(&privateKey.PublicKey)
	require.NoError(t, err)
	assert.JSONEq(t, string(payload), string(raw))
}

func TestSignPayload_NilSigner(t *testing.T) {
	_, err := crypto.SignPayload([]byte("test"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing signer")
}

func TestSign_InvalidObject(t *testing.T) {
	signer, _ := newTestSigner(t)

	_, err := crypto.Sign(make(chan int), signer)
	require.Error(t, err)
}
