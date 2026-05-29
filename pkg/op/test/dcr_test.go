// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios
//
// Dynamic Client Registration (RFC 7591 / RFC 7592) tests.

package op_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/op"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

func TestDCR_RegistrationEndpoint(t *testing.T) {
	provider := newTestProvider(&op.Config{
		CryptoKey:             [32]byte{},
		CryptoKeyId:           "test-key-id",
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		RegistrationSupported: true,
	})
	require.NotNil(t, provider)

	// Verify that the registration endpoint exists
	endpoint := provider.RegistrationEndpoint()
	require.NotNil(t, endpoint)
	assert.Equal(t, "/register", endpoint.Relative())
}

func TestDCR_RegisterClient_RequiresAuth(t *testing.T) {
	provider := newTestProvider(&op.Config{
		CryptoKey:             [32]byte{},
		CryptoKeyId:           "test-key-id",
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		RegistrationSupported: true,
	})
	require.NotNil(t, provider)

	// Build a registration request without auth (should fail)
	reqBody := op.RegistrationRequest{
		RedirectURIs:  []string{"https://client.example.com/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		ClientName:    "Test Client",
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Make a POST to /register without an Authorization header
	r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := op.CreateRouter(provider)
	router.ServeHTTP(w, r)

	// Should return 401 Unauthorized because no initial access token was provided
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Per RFC 6750 Section 3, WWW-Authenticate header is required for 401
	wwwAuth := w.Result().Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, "error=\"invalid_token\"")

	var resp map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_token", resp["error"])
}

func TestDCR_RegisterClient_Success(t *testing.T) {
	provider := newTestProvider(&op.Config{
		CryptoKey:             [32]byte{},
		CryptoKeyId:           "test-key-id",
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		RegistrationSupported: true,
	})
	require.NotNil(t, provider)

	reqBody := op.RegistrationRequest{
		RedirectURIs:            []string{"https://client.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Test Client",
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   "openid profile email",
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer test-admin-token")
	w := httptest.NewRecorder()

	router := op.CreateRouter(provider)
	router.ServeHTTP(w, r)

	// Should return 201 Created
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp op.ClientRegistrationResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Validate the response fields
	assert.NotEmpty(t, resp.ClientID)
	assert.NotEmpty(t, resp.ClientSecret)
	assert.NotEmpty(t, resp.RegistrationAccessToken)
	assert.NotEmpty(t, resp.RegistrationURI)
	assert.Equal(t, "https://client.example.com/callback", resp.RedirectURIs[0])
	assert.Equal(t, "authorization_code", resp.GrantTypes[0])
	assert.Equal(t, "code", resp.ResponseTypes[0])
	assert.Equal(t, "Test Client", resp.ClientName)
	assert.Equal(t, "client_secret_basic", resp.TokenEndpointAuthMethod)
}

func TestDCR_RegisterClient_NoRedirectURIs(t *testing.T) {
	provider := newTestProvider(&op.Config{
		CryptoKey:             [32]byte{},
		CryptoKeyId:           "test-key-id",
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		RegistrationSupported: true,
	})
	require.NotNil(t, provider)

	// Request without redirect_uris (required for authorization_code)
	reqBody := op.RegistrationRequest{
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		ClientName:    "Test Client",
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer test-admin-token")
	w := httptest.NewRecorder()

	router := op.CreateRouter(provider)
	router.ServeHTTP(w, r)

	// Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDCR_ClientConfigEndpoint_NotFound(t *testing.T) {
	// Test that accessing a non-existent client returns 401
	r := httptest.NewRequest(http.MethodGet, "/register/nonexistent-client", nil)
	r.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()

	provider := newTestProvider(&op.Config{
		CryptoKey:             [32]byte{},
		CryptoKeyId:           "test-key-id",
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		RegistrationSupported: true,
	})

	router := op.CreateRouter(provider)
	router.ServeHTTP(w, r)

	// Should return 401 because the registration access token is invalid
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDCR_Discovery_RegistrationEndpoint(t *testing.T) {
	provider := newTestProvider(&op.Config{
		CryptoKey:             [32]byte{},
		CryptoKeyId:           "test-key-id",
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		RegistrationSupported: true,
	})
	require.NotNil(t, provider)

	// Fetch the discovery document
	r := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	router := op.CreateRouter(provider)
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var discovery protocol.DiscoveryConfiguration
	err := json.Unmarshal(w.Body.Bytes(), &discovery)
	require.NoError(t, err)

	// Verify registration_endpoint is present
	assert.Contains(t, discovery.RegistrationEndpoint, "/register")
}

func TestDCR_RegisterClient_NoTokenEndpointAuth(t *testing.T) {
	provider := newTestProvider(&op.Config{
		CryptoKey:             [32]byte{},
		CryptoKeyId:           "test-key-id",
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		RegistrationSupported: true,
	})
	require.NotNil(t, provider)

	// Register a client with token_endpoint_auth_method = "none"
	reqBody := op.RegistrationRequest{
		RedirectURIs:            []string{"https://client.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Public Client",
		TokenEndpointAuthMethod: "none",
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer test-admin-token")
	w := httptest.NewRecorder()

	router := op.CreateRouter(provider)
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp op.ClientRegistrationResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Public clients (auth_method=none) should not get a client_secret
	assert.Empty(t, resp.ClientSecret)
	assert.NotEmpty(t, resp.ClientID)
}

func TestDCR_InvalidRequestBodies(t *testing.T) {
	provider := newTestProvider(&op.Config{
		CryptoKey:             [32]byte{},
		CryptoKeyId:           "test-key-id",
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		RegistrationSupported: true,
	})
	require.NotNil(t, provider)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "invalid JSON",
			body:       "not-json",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty object",
			body:       "{}",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid auth method",
			body:       `{"redirect_uris":["https://example.com/callback"],"token_endpoint_auth_method":"invalid"}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader([]byte(tt.body)))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer test-admin-token")
			w := httptest.NewRecorder()

			router := op.CreateRouter(provider)
			router.ServeHTTP(w, r)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}
