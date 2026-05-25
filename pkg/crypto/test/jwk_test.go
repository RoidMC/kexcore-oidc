// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/emmansun/gmsm/sm9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
)

func TestNewSM2JWK(t *testing.T) {
	key, err := crypto.SM2GenerateKey()
	require.NoError(t, err)

	jwk := crypto.NewSM2JWK(&key.PublicKey, "test-kid", "sig")

	assert.Equal(t, "EC", jwk.Kty)
	assert.Equal(t, "SM2-P-256", jwk.Crv)
	assert.Equal(t, crypto.SGD_SM3_SM2, jwk.Alg)
	assert.Equal(t, "test-kid", jwk.Kid)
	assert.Equal(t, "sig", jwk.Use)
	assert.NotEmpty(t, jwk.X)
	assert.NotEmpty(t, jwk.Y)
}

func TestNewSM9SignJWK(t *testing.T) {
	masterKey, err := crypto.SM9GenerateSignMasterKey()
	require.NoError(t, err)

	jwk, err := crypto.NewSM9SignJWK(masterKey.PublicKey(), "test-kid", "sig", 1)
	require.NoError(t, err)

	assert.Equal(t, "EC", jwk.Kty)
	assert.Equal(t, "SM9", jwk.Crv)
	assert.Equal(t, crypto.SGD_SM3_SM9, jwk.Alg)
	assert.Equal(t, "test-kid", jwk.Kid)
	assert.Equal(t, "sig", jwk.Use)
	assert.NotEmpty(t, jwk.X)
	assert.NotEmpty(t, jwk.Y)
	assert.Equal(t, 1, jwk.Hid)
}

func TestParseSM9SignMasterPublicKey(t *testing.T) {
	masterKey, err := crypto.SM9GenerateSignMasterKey()
	require.NoError(t, err)

	jwk, err := crypto.NewSM9SignJWK(masterKey.PublicKey(), "test-kid", "sig", 1)
	require.NoError(t, err)

	parsed, err := crypto.ParseSM9SignMasterPublicKey(jwk.X, jwk.Y)
	require.NoError(t, err)

	assert.True(t, masterKey.PublicKey().Equal(parsed))
}

func TestSM2PublicKeyFromJWK(t *testing.T) {
	key, err := crypto.SM2GenerateKey()
	require.NoError(t, err)

	jwk := crypto.NewSM2JWK(&key.PublicKey, "test-kid", "sig")

	parsed, err := crypto.SM2PublicKeyFromJWK(jwk.Crv, jwk.X, jwk.Y)
	require.NoError(t, err)

	assert.True(t, key.PublicKey.Equal(parsed))
}

func TestSM2PublicKeyFromJWK_InvalidCurve(t *testing.T) {
	_, err := crypto.SM2PublicKeyFromJWK("P-256", "AQID", "AQID")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported SM2 curve")
}

func TestSM2PublicKeyFromJWK_InvalidPoint(t *testing.T) {
	_, err := crypto.SM2PublicKeyFromJWK("SM2-P-256",
		base64.RawURLEncoding.EncodeToString([]byte{0x01}),
		base64.RawURLEncoding.EncodeToString([]byte{0x02}))
	assert.Error(t, err)
}

func TestParseJWKSBytes(t *testing.T) {
	sm2Key, err := crypto.SM2GenerateKey()
	require.NoError(t, err)

	sm9MasterKey, err := crypto.SM9GenerateSignMasterKey()
	require.NoError(t, err)

	sm2JWK := crypto.NewSM2JWK(&sm2Key.PublicKey, "sm2-kid", "sig")
	sm9JWK, err := crypto.NewSM9SignJWK(sm9MasterKey.PublicKey(), "sm9-kid", "sig", 1)
	require.NoError(t, err)

	jwks := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": sm2JWK.Kty, "crv": sm2JWK.Crv, "x": sm2JWK.X, "y": sm2JWK.Y,
				"alg": sm2JWK.Alg, "kid": sm2JWK.Kid, "use": sm2JWK.Use,
			},
			map[string]interface{}{
				"kty": sm9JWK.Kty, "crv": sm9JWK.Crv, "x": sm9JWK.X, "y": sm9JWK.Y,
				"hid": sm9JWK.Hid,
				"alg": sm9JWK.Alg, "kid": sm9JWK.Kid, "use": sm9JWK.Use,
			},
			map[string]interface{}{
				"kty": "RSA", "kid": "rsa-kid", "alg": "RS256", "use": "sig",
				"n": "AQID", "e": "AQAB",
			},
		},
	}

	data, err := json.Marshal(jwks)
	require.NoError(t, err)

	keys, err := crypto.ParseJWKSBytes(data)
	require.NoError(t, err)

	assert.Len(t, keys, 2, "should parse SM2 and SM9 keys, skip RSA")

	sm2Found := crypto.FindJWKSKey(keys, "sm2-kid", crypto.SGD_SM3_SM2)
	require.NotNil(t, sm2Found)
	assert.Equal(t, crypto.SGD_SM3_SM2, sm2Found.Alg)
	assert.IsType(t, &ecdsa.PublicKey{}, sm2Found.Key)

	sm9Found := crypto.FindJWKSKey(keys, "sm9-kid", crypto.SGD_SM3_SM9)
	require.NotNil(t, sm9Found)
	assert.Equal(t, crypto.SGD_SM3_SM9, sm9Found.Alg)
	assert.IsType(t, &sm9.SignMasterPublicKey{}, sm9Found.Key)
}

func TestFindJWKSKey(t *testing.T) {
	keys := []crypto.JWKSKey{
		{Kid: "k1", Alg: "RS256", Key: "rsa"},
		{Kid: "k2", Alg: crypto.SGD_SM3_SM2, Key: "sm2"},
		{Kid: "k3", Alg: crypto.SGD_SM3_SM9, Key: "sm9"},
	}

	assert.Equal(t, "sm2", crypto.FindJWKSKey(keys, "k2", crypto.SGD_SM3_SM2).Key)
	assert.Equal(t, "sm9", crypto.FindJWKSKey(keys, "k3", crypto.SGD_SM3_SM9).Key)
	assert.Equal(t, "rsa", crypto.FindJWKSKey(keys, "k1", "RS256").Key)
	assert.Nil(t, crypto.FindJWKSKey(keys, "missing", crypto.SGD_SM3_SM2))
	assert.Equal(t, "sm2", crypto.FindJWKSKey(keys, "", crypto.SGD_SM3_SM2).Key, "empty kid should match first")
}

func TestIsSM2Algorithm(t *testing.T) {
	assert.True(t, crypto.IsSM2Algorithm(crypto.SGD_SM3_SM2))
	assert.True(t, crypto.IsSM2Algorithm("SM2-SM3"))
	assert.False(t, crypto.IsSM2Algorithm("RS256"))
	assert.False(t, crypto.IsSM2Algorithm(crypto.SGD_SM3_SM9))
}

func TestIsSM9Algorithm(t *testing.T) {
	assert.True(t, crypto.IsSM9Algorithm(crypto.SGD_SM3_SM9))
	assert.False(t, crypto.IsSM9Algorithm("RS256"))
	assert.False(t, crypto.IsSM9Algorithm(crypto.SGD_SM3_SM2))
}

func TestVerifySM2JWSSignature(t *testing.T) {
	key, err := crypto.SM2GenerateKey()
	require.NoError(t, err)

	signingInput := []byte(base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"SGD_SM3_SM2"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("test payload")))

	h, err := crypto.GetHashAlgorithm(crypto.SGD_SM3_SM2)
	require.NoError(t, err)
	h.Write(signingInput)
	digest := h.Sum(nil)

	sig, err := crypto.SM2Sign(key, digest)
	require.NoError(t, err)

	err = crypto.VerifySM2JWSSignature(signingInput, sig, &key.PublicKey)
	assert.NoError(t, err)

	err = crypto.VerifySM2JWSSignature([]byte("wrong input"), sig, &key.PublicKey)
	assert.Error(t, err)
}

func TestVerifySM9JWSSignature(t *testing.T) {
	uid := []byte("test@example.com")
	masterKey, err := crypto.SM9GenerateSignMasterKey()
	require.NoError(t, err)

	userKey, err := crypto.SM9GenerateSignUserKey(masterKey, uid)
	require.NoError(t, err)

	signingInput := []byte(base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"SGD_SM3_SM9","uid":"test@example.com"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("test payload")))

	h, err := crypto.GetHashAlgorithm(crypto.SGD_SM3_SM9)
	require.NoError(t, err)
	h.Write(signingInput)
	digest := h.Sum(nil)

	sig, err := crypto.SM9Sign(userKey, digest)
	require.NoError(t, err)

	err = crypto.VerifySM9JWSSignature(signingInput, sig, masterKey.PublicKey(), uid)
	assert.NoError(t, err)

	err = crypto.VerifySM9JWSSignature(signingInput, sig, masterKey.PublicKey(), []byte("wrong-uid"))
	assert.Error(t, err)

	err = crypto.VerifySM9JWSSignature([]byte("wrong input"), sig, masterKey.PublicKey(), uid)
	assert.Error(t, err)
}

func TestBuildSigningInput(t *testing.T) {
	header := map[string]string{"alg": "SGD_SM3_SM2"}
	payload := []byte("test payload")

	input, err := crypto.BuildSigningInput(header, payload)
	require.NoError(t, err)

	expected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"SGD_SM3_SM2"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	assert.Equal(t, expected, string(input))
}
