// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package profile_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/roidmc/kexcore-oidc/v1/pkg/client/profile"
)

var ecKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwwOZSU4GlP7ps/Wp
V6o0qRwxultdfYo/uUuj48QZjSuhRANCAATMiI2Han+ABKmrk5CNlxRAGC61w4d3
G4TAeuBpyzqJ7x/6NjCxoQzJzZHtNjIfjVATI59XFZWF59GhtSZbShAr
-----END PRIVATE KEY-----`)

const testIssuer = "https://test-issuer.example.com"
const testClientID = "test-client-id"
const testKeyID = "test-key-id"

func TestNewJWTProfileTokenSource_EmptyIssuer(t *testing.T) {
	_, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		"",
		testClientID,
		testKeyID,
		ecKey,
		[]string{"openid"},
		profile.WithStaticTokenEndpoint(testIssuer, "https://token.example.com/token"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer must not be empty")
}

func TestNewJWTProfileTokenSource_EmptyClientID(t *testing.T) {
	_, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		testIssuer,
		"",
		testKeyID,
		ecKey,
		[]string{"openid"},
		profile.WithStaticTokenEndpoint(testIssuer, "https://token.example.com/token"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "clientID must not be empty")
}

func TestNewJWTProfileTokenSource_EmptyKey(t *testing.T) {
	_, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		testIssuer,
		testClientID,
		testKeyID,
		nil,
		[]string{"openid"},
		profile.WithStaticTokenEndpoint(testIssuer, "https://token.example.com/token"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key must not be empty")
}

func TestNewJWTProfileTokenSource_InvalidKey(t *testing.T) {
	_, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		testIssuer,
		testClientID,
		testKeyID,
		[]byte("not-a-valid-key"),
		[]string{"openid"},
		profile.WithStaticTokenEndpoint(testIssuer, "https://token.example.com/token"),
	)
	assert.Error(t, err)
}

func TestNewJWTProfileTokenSource_WithStaticEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"access_token": "static-ep-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	src, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		testIssuer,
		testClientID,
		testKeyID,
		ecKey,
		[]string{"openid", "profile"},
		profile.WithStaticTokenEndpoint(testIssuer, server.URL),
		profile.WithHTTPClient(server.Client()),
	)
	require.NoError(t, err)

	token, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "static-ep-token", token.AccessToken)
}

func TestWithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 15 * time.Second}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"access_token": "custom-client-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	src, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		testIssuer,
		testClientID,
		testKeyID,
		ecKey,
		[]string{"openid"},
		profile.WithStaticTokenEndpoint(testIssuer, server.URL),
		profile.WithHTTPClient(customClient),
	)
	require.NoError(t, err)

	token, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "custom-client-token", token.AccessToken)
}

func TestWithAssertionDuration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"access_token": "duration-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	src, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		testIssuer,
		testClientID,
		testKeyID,
		ecKey,
		[]string{"openid"},
		profile.WithStaticTokenEndpoint(testIssuer, server.URL),
		profile.WithHTTPClient(server.Client()),
		profile.WithAssertionDuration(30*time.Minute),
	)
	require.NoError(t, err)

	token, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "duration-token", token.AccessToken)
}

func TestTokenCtx_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		resp := map[string]any{
			"access_token": "access-token-xxx",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	src, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		testIssuer,
		testClientID,
		testKeyID,
		ecKey,
		[]string{"openid"},
		profile.WithStaticTokenEndpoint(testIssuer, server.URL),
		profile.WithHTTPClient(server.Client()),
	)
	require.NoError(t, err)

	token, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "access-token-xxx", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.False(t, token.Expiry.IsZero())
}

func TestTokenCtx_ContextPropagation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"access_token": "ctx-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	src, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		testIssuer,
		testClientID,
		testKeyID,
		ecKey,
		[]string{"openid"},
		profile.WithStaticTokenEndpoint(testIssuer, server.URL),
		profile.WithHTTPClient(server.Client()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token, err := src.TokenCtx(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ctx-token", token.AccessToken)
}

func TestTokenCtx_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	src, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		testIssuer,
		testClientID,
		testKeyID,
		ecKey,
		[]string{"openid"},
		profile.WithStaticTokenEndpoint(testIssuer, server.URL),
		profile.WithHTTPClient(server.Client()),
	)
	require.NoError(t, err)

	_, err = src.Token()
	assert.Error(t, err)
}

func TestTokenSourceInterface(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"access_token": "iface-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	src, err := profile.NewJWTProfileTokenSource(
		context.Background(),
		testIssuer,
		testClientID,
		testKeyID,
		ecKey,
		[]string{"openid"},
		profile.WithStaticTokenEndpoint(testIssuer, server.URL),
		profile.WithHTTPClient(server.Client()),
	)
	require.NoError(t, err)

	var ts oauth2.TokenSource = src
	token, err := ts.Token()
	require.NoError(t, err)
	assert.Equal(t, "iface-token", token.AccessToken)
}
