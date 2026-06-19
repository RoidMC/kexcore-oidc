// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zcrypto "github.com/roidmc/kexcore-oidc/v2/pkg/crypto"
)

func newTestSigner(t *testing.T) (*zcrypto.Signer, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := zcrypto.NewSigner("RS256", privateKey, "")
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

	jwsCompact, err := zcrypto.Sign(payload, signer)
	require.NoError(t, err)
	assert.NotEmpty(t, jwsCompact)

	_, err = jws.Verify([]byte(jwsCompact), jws.WithKey(jwa.RS256(), &privateKey.PublicKey))
	require.NoError(t, err)

	jwsParsed, err := jws.Parse([]byte(jwsCompact))
	require.NoError(t, err)

	var decoded testPayload
	err = json.Unmarshal(jwsParsed.Payload(), &decoded)
	require.NoError(t, err)
	assert.Equal(t, payload.Sub, decoded.Sub)
	assert.Equal(t, payload.Email, decoded.Email)
}

func TestSignPayload_Ok(t *testing.T) {
	signer, privateKey := newTestSigner(t)
	payload := []byte(`{"sub":"user-2","email":"user2@example.com"}`)

	jwsCompact, err := zcrypto.SignPayload(payload, signer)
	require.NoError(t, err)
	assert.NotEmpty(t, jwsCompact)

	payloadBytes, err := jws.Verify([]byte(jwsCompact), jws.WithKey(jwa.RS256(), &privateKey.PublicKey))
	require.NoError(t, err)
	assert.JSONEq(t, string(payload), string(payloadBytes))
}

func TestSignPayload_NilSigner(t *testing.T) {
	_, err := zcrypto.SignPayload([]byte("test"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing signer")
}

func TestSign_InvalidObject(t *testing.T) {
	signer, _ := newTestSigner(t)

	_, err := zcrypto.Sign(make(chan int), signer)
	require.Error(t, err)
}

func TestSigner_ReturnsAlgorithm(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := zcrypto.NewSigner("RS256", privateKey, "key-1")
	require.NoError(t, err)
	assert.Equal(t, "RS256", signer.Algorithm())
}

func TestSigner_KeyID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := zcrypto.NewSigner("RS256", privateKey, "my-key-id")
	require.NoError(t, err)

	jwsCompact, err := signer.Sign([]byte(`{"test":"data"}`))
	require.NoError(t, err)

	jwsParsed, err := jws.Parse([]byte(jwsCompact))
	require.NoError(t, err)

	require.Len(t, jwsParsed.Signatures(), 1)
	kid, _ := jwsParsed.Signatures()[0].ProtectedHeaders().KeyID()
	assert.Equal(t, "my-key-id", kid)
}
