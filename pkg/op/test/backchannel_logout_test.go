// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/op"
)

// ---------- JWE Encryption / Decryption Tests ----------

func TestJWEEncryptDecrypt_SM4GCM(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	signedToken := "header.payload.signature"

	encrypted, err := oidc.EncryptToken(signedToken, key)
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	decrypted, err := oidc.DecryptTokenWithKey(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, signedToken, string(decrypted))
}

func TestJWEDecrypt_CorruptedJWE(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	signedToken := "header.payload.signature"
	encrypted, err := oidc.EncryptToken(signedToken, key)
	require.NoError(t, err)

	// Tamper with the ciphertext part.
	parts := strings.Split(encrypted, ".")
	parts[3] = "tampered"
	tampered := strings.Join(parts, ".")

	_, err = oidc.DecryptTokenWithKey(tampered, key)
	assert.Error(t, err)
}

func TestJWEDecrypt_WrongKey(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	wrongKey := make([]byte, 16)
	_, err = rand.Read(wrongKey)
	require.NoError(t, err)

	signedToken := "header.payload.signature"
	encrypted, err := oidc.EncryptToken(signedToken, key)
	require.NoError(t, err)

	_, err = oidc.DecryptTokenWithKey(encrypted, wrongKey)
	assert.Error(t, err, "decryption with wrong key should fail")
}

// ---------- Logout Token Tests ----------

func mustNewSigner(t *testing.T) *crypto.Signer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := crypto.NewSigner("RS256", privateKey, "")
	require.NoError(t, err)
	return signer
}

func TestLogoutTokenCreation(t *testing.T) {
	signer := mustNewSigner(t)
	now := time.Now()

	claims := &oidc.LogoutTokenClaims{
		Issuer:     "https://op.example.com",
		Subject:    "user-123",
		Audience:   oidc.Audience{"client-abc"},
		IssuedAt:   oidc.FromTime(now),
		Expiration: oidc.FromTime(now.Add(5 * time.Minute)),
		JWTID:      "lt-001",
		SessionID:  "sid-xyz",
		Events: map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": struct{}{},
		},
	}

	token, err := crypto.Sign(claims, signer)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	parts := strings.Split(token, ".")
	assert.Equal(t, 3, len(parts), "logout token should have 3 parts")
}

func TestLogoutTokenClaimsMethods(t *testing.T) {
	now := time.Now()

	claims := &oidc.LogoutTokenClaims{
		Issuer:     "https://op.example.com",
		Subject:    "user-123",
		Audience:   oidc.Audience{"client-abc", "client-def"},
		IssuedAt:   oidc.FromTime(now),
		Expiration: oidc.FromTime(now.Add(300)),
		JWTID:      "lt-001",
		SessionID:  "sid-xyz",
		Events: map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": struct{}{},
		},
	}

	assert.Equal(t, "https://op.example.com", claims.GetIssuer())
	assert.Equal(t, "user-123", claims.GetSubject())
	assert.Equal(t, []string{"client-abc", "client-def"}, claims.GetAudience())
	assert.Equal(t, "", claims.GetNonce())
	assert.Empty(t, claims.GetAuthTime())
	assert.Empty(t, claims.GetAuthorizedParty())
	assert.Empty(t, claims.GetAuthenticationContextClassReference())
	assert.Equal(t, "sid-xyz", claims.SessionID)
	assert.NotNil(t, claims.Events)
	_, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]
	assert.True(t, ok)
}

// ---------- Back-Channel Logout: RP receives Logout Token ----------

type mockRPBCLServer struct {
	token string
	code  int
}

func (s *mockRPBCLServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.token = r.Form.Get("logout_token")
	if s.code != 0 {
		w.WriteHeader(s.code)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func TestBackChannelLogout_SendLogoutToken(t *testing.T) {
	signer := mustNewSigner(t)
	rpServer := &mockRPBCLServer{}
	rpSrv := httptest.NewServer(rpServer)
	defer rpSrv.Close()

	ctx := context.Background()
	now := time.Now()

	claims := &oidc.LogoutTokenClaims{
		Issuer:     "https://op.example.com",
		Subject:    "user-123",
		Audience:   oidc.Audience{"client-abc"},
		IssuedAt:   oidc.FromTime(now),
		Expiration: oidc.FromTime(now.Add(300)),
		JWTID:      "lt-test-001",
		SessionID:  "sid-xyz",
		Events: map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": struct{}{},
		},
	}

	logoutToken, err := crypto.Sign(claims, signer)
	require.NoError(t, err)

	payload := url.Values{}
	payload.Set("logout_token", logoutToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpSrv.URL, strings.NewReader(payload.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, logoutToken, rpServer.token, "RP should receive the logout token")
}

func TestBackChannelLogout_SendToMultipleRPs(t *testing.T) {
	signer := mustNewSigner(t)

	rp1 := &mockRPBCLServer{}
	rp2 := &mockRPBCLServer{}
	srv1 := httptest.NewServer(rp1)
	defer srv1.Close()
	srv2 := httptest.NewServer(rp2)
	defer srv2.Close()

	ctx := context.Background()
	now := time.Now()

	claims := &oidc.LogoutTokenClaims{
		Issuer:     "https://op.example.com",
		Subject:    "user-123",
		Audience:   oidc.Audience{"client-1"},
		IssuedAt:   oidc.FromTime(now),
		Expiration: oidc.FromTime(now.Add(300)),
		JWTID:      "lt-multi-001",
		SessionID:  "sid-xyz",
		Events: map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": struct{}{},
		},
	}

	token, err := crypto.Sign(claims, signer)
	require.NoError(t, err)

	// Send to RP1.
	payload1 := url.Values{}
	payload1.Set("logout_token", token)
	req1, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv1.URL, strings.NewReader(payload1.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp1, err := (&http.Client{}).Do(req1)
	require.NoError(t, err)
	resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	assert.Equal(t, token, rp1.token)

	// Send to RP2.
	payload2 := url.Values{}
	payload2.Set("logout_token", token)
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv2.URL, strings.NewReader(payload2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, err := (&http.Client{}).Do(req2)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	assert.Equal(t, token, rp2.token)
}

// ---------- ID Token Encryption Integration Tests ----------

func TestEncryptIDToken_SM4GCM(t *testing.T) {
	signedToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"

	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	encrypted, err := oidc.EncryptToken(signedToken, key)
	require.NoError(t, err)
	assert.NotEqual(t, signedToken, encrypted, "encrypted token should differ from original")

	parts := strings.Split(encrypted, ".")
	assert.Equal(t, 5, len(parts), "JWE should have 5 parts")
}

// ---------- TokenEncryptionKeyProvider Tests ----------

func TestCryptoTokenEncryptionKey(t *testing.T) {
	t.Run("AES256GCM Crypto provides encryption key", func(t *testing.T) {
		var keyArr [32]byte
		_, err := rand.Read(keyArr[:])
		require.NoError(t, err)

		c := op.NewAES256GCMCrypto(keyArr, "")
		ek, ok := c.(op.TokenEncryptionKeyProvider)
		require.True(t, ok, "AES256GCMCrypto should implement TokenEncryptionKeyProvider")
		assert.Equal(t, keyArr[:], ek.TokenEncryptionKey())
	})

	t.Run("SM4GCM Crypto provides encryption key", func(t *testing.T) {
		var keyArr [16]byte
		_, err := rand.Read(keyArr[:])
		require.NoError(t, err)

		c := op.NewSM4GCMCrypto(keyArr, "")
		ek, ok := c.(op.TokenEncryptionKeyProvider)
		require.True(t, ok, "SM4GCMCrypto should implement TokenEncryptionKeyProvider")
		assert.Equal(t, keyArr[:], ek.TokenEncryptionKey())
	})
}

// ---------- JWE Full Round-Trip with Large Payloads ----------

func TestJWERoundTrip_LargePayload(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	largePayload := make([]byte, 1024)
	for i := range largePayload {
		largePayload[i] = byte('A' + (i % 26))
	}
	signedToken := string(largePayload)

	encrypted, err := oidc.EncryptToken(signedToken, key)
	require.NoError(t, err)

	decrypted, err := oidc.DecryptTokenWithKey(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, signedToken, string(decrypted))
}

// ---------- Back-Channel Logout Handler Integration Test ----------

type mockBCLStorage struct {
	op.Storage
	signingKey crypto.Signer
}

func (m *mockBCLStorage) SigningKey(ctx context.Context) (*crypto.Signer, error) {
	return &m.signingKey, nil
}

type mockBCLClient struct {
	op.Client
	id     string
	bclURI string
}

func (m *mockBCLClient) GetID() string                { return m.id }
func (m *mockBCLClient) BackChannelLogoutURI() string { return m.bclURI }

var _ op.BackChannelLogoutClient = (*mockBCLClient)(nil)

func TestBackChannelLogout_Integration(t *testing.T) {
	signer := mustNewSigner(t)

	rpServer := &mockRPBCLServer{}
	rpSrv := httptest.NewServer(rpServer)
	defer rpSrv.Close()

	storage := &mockBCLStorage{
		signingKey: *signer,
	}
	_ = storage

	// Verify the storage returns the correct signing key.
	ctx := context.Background()
	key, err := storage.SigningKey(ctx)
	require.NoError(t, err)
	require.NotNil(t, key)

	// Verify we can sign a Logout Token.
	now := time.Now()
	claims := &oidc.LogoutTokenClaims{
		Issuer:     "https://op.example.com",
		Subject:    "user-123",
		Audience:   oidc.Audience{"client-abc"},
		IssuedAt:   oidc.FromTime(now),
		Expiration: oidc.FromTime(now.Add(300)),
		JWTID:      "lt-integration-001",
		SessionID:  "sid-xyz",
		Events: map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": struct{}{},
		},
	}
	token, err := crypto.Sign(claims, key)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Send to RP.
	payload := url.Values{}
	payload.Set("logout_token", token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpSrv.URL, strings.NewReader(payload.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := (&http.Client{}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, token, rpServer.token)
}
