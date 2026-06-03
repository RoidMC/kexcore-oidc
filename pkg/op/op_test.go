// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package op_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/muhlemmer/gu"
	"github.com/roidmc/kexcore-oidc/example/server/storage"
	"github.com/roidmc/kexcore-oidc/pkg/op"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

var (
	testProvider op.OpenIDProvider
	testConfig   = &op.Config{
		CryptoKey:                sha256.Sum256([]byte("test")),
		CryptoKeyId:              "key1",
		DefaultLogoutRedirectURI: pathLoggedOut,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedClaims:          op.DefaultSupportedClaims,
		SupportedUILocales:       []language.Tag{language.English},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
	}
)

const (
	testIssuer    = "https://localhost:9998/"
	pathLoggedOut = "/logged-out"
)

func init() {
	storage.RegisterClients(
		storage.NativeClient("native"),
		storage.WebClient("web", "secret", "https://example.com"),
		storage.DeviceClient("device", "secret"),
		storage.WebClient("api", "secret"),
	)

	testProvider = newTestProvider(testConfig)
}

func newTestProvider(config *op.Config) op.OpenIDProvider {
	return newTestProviderWithCrypto(config, nil)
}

func newTestProviderWithCrypto(config *op.Config, crypto op.Crypto) op.OpenIDProvider {
	stor := storage.NewStorage(storage.NewUserStore(testIssuer))
	keySet := &op.OpenIDKeySet{stor}
	opts := []op.Option{
		op.WithAllowInsecure(),
		op.WithAccessTokenKeySet(keySet),
		op.WithIDTokenHintKeySet(keySet),
	}
	if crypto != nil {
		opts = append(opts, op.WithCrypto(crypto))
	}
	provider, err := op.NewProvider(config, stor, op.StaticIssuer(testIssuer), opts...)
	if err != nil {
		panic(err)
	}
	return provider
}

type routesTestStorage interface {
	op.Storage
	AuthRequestDone(id string) error
}

func mapAsValues(m map[string]string) string {
	values := make(url.Values, len(m))
	for k, v := range m {
		values.Set(k, v)
	}
	return values.Encode()
}

func TestRoutes(t *testing.T) {
	storage := testProvider.Storage().(routesTestStorage)
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)

	client, err := storage.GetClientByClientID(ctx, "web")
	require.NoError(t, err)

	oidcAuthReq := &protocol.AuthRequest{
		ClientID:     client.GetID(),
		RedirectURI:  "https://example.com",
		MaxAge:       gu.Ptr[uint](300),
		Scopes:       protocol.SpaceDelimitedArray{protocol.ScopeOpenID, protocol.ScopeOfflineAccess, protocol.ScopeEmail, protocol.ScopeProfile, protocol.ScopePhone},
		ResponseType: protocol.ResponseTypeCode,
	}

	authReq, err := storage.CreateAuthRequest(ctx, oidcAuthReq, "id1")
	require.NoError(t, err)
	storage.AuthRequestDone(authReq.GetID())
	storage.SaveAuthCode(ctx, authReq.GetID(), "123")

	accessToken, refreshToken, _, err := op.CreateAccessToken(ctx, authReq, op.AccessTokenTypeBearer, testProvider, client, "")
	require.NoError(t, err)
	accessTokenRevoke, _, _, err := op.CreateAccessToken(ctx, authReq, op.AccessTokenTypeBearer, testProvider, client, "")
	require.NoError(t, err)
	idToken, err := op.CreateIDToken(ctx, testIssuer, authReq, time.Hour, accessToken, "123", storage, client)
	require.NoError(t, err)
	jwtToken, _, _, err := op.CreateAccessToken(ctx, authReq, op.AccessTokenTypeJWT, testProvider, client, "")
	require.NoError(t, err)

	oidcAuthReq.IDTokenHint = idToken

	serverURL, err := url.Parse(testIssuer)
	require.NoError(t, err)

	type basicAuth struct {
		username, password string
	}

	tests := []struct {
		name           string
		method         string
		path           string
		basicAuth      *basicAuth
		header         map[string]string
		values         map[string]string
		body           map[string]string
		wantCode       int
		headerContains map[string]string
		json           string   // test for exact json output
		contains       []string // when the body output is not constant, we just check for snippets to be present in the response
		expiresIn      uint64   // if >0, checks expires_in is within ±2 of this value
	}{
		{
			name:     "health",
			method:   http.MethodGet,
			path:     "/healthz",
			wantCode: http.StatusOK,
			json:     `{"status":"ok"}`,
		},
		{
			name:     "ready",
			method:   http.MethodGet,
			path:     "/ready",
			wantCode: http.StatusOK,
			json:     `{"status":"ok"}`,
		},
		{
			name:     "discovery",
			method:   http.MethodGet,
			path:     protocol.DiscoveryEndpoint,
			wantCode: http.StatusOK,
			json:     `{"issuer":"https://localhost:9998/","authorization_endpoint":"https://localhost:9998/authorize","token_endpoint":"https://localhost:9998/oauth/token","introspection_endpoint":"https://localhost:9998/oauth/introspect","userinfo_endpoint":"https://localhost:9998/userinfo","revocation_endpoint":"https://localhost:9998/revoke","end_session_endpoint":"https://localhost:9998/end_session","device_authorization_endpoint":"https://localhost:9998/device_authorization","jwks_uri":"https://localhost:9998/keys","scopes_supported":["openid","profile","email","phone","address","offline_access"],"response_types_supported":["code","id_token","id_token token"],"grant_types_supported":["authorization_code","implicit","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:jwt-bearer","urn:ietf:params:oauth:grant-type:device_code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256","SGD_SM3_SM2"],"request_object_signing_alg_values_supported":["RS256","SGD_SM3_SM2"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post","private_key_jwt"],"token_endpoint_auth_signing_alg_values_supported":["RS256","SGD_SM3_SM2"],"revocation_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post","private_key_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["RS256","SGD_SM3_SM2"],"introspection_endpoint_auth_methods_supported":["client_secret_basic","private_key_jwt"],"introspection_endpoint_auth_signing_alg_values_supported":["RS256","SGD_SM3_SM2"],"claims_supported":["sub","aud","exp","iat","iss","auth_time","nonce","acr","amr","c_hash","at_hash","act","scopes","client_id","azp","preferred_username","name","family_name","given_name","locale","email","email_verified","phone_number","phone_number_verified"],"code_challenge_methods_supported":["S256"],"ui_locales_supported":["en"],"request_parameter_supported":true}`,
		},
		{
			name:   "authorization",
			method: http.MethodGet,
			path:   testProvider.AuthorizationEndpoint().Relative(),
			values: map[string]string{
				"client_id":     client.GetID(),
				"redirect_uri":  "https://example.com",
				"scope":         protocol.SpaceDelimitedArray{protocol.ScopeOpenID, protocol.ScopeOfflineAccess}.String(),
				"response_type": string(protocol.ResponseTypeCode),
			},
			wantCode:       http.StatusFound,
			headerContains: map[string]string{"Location": "/login/username?authRequestID="},
		},
		{
			name:           "authorization callback",
			method:         http.MethodGet,
			path:           testProvider.AuthorizationEndpoint().Relative() + "/callback",
			values:         map[string]string{"id": authReq.GetID()},
			wantCode:       http.StatusFound,
			headerContains: map[string]string{"Location": "https://example.com?code="},
			contains: []string{
				`<a href="https://example.com?code=`,
				">Found</a>.",
			},
		},
		{
			// This call will fail. A successful test is already
			// part of client/integration_test.go
			name:   "code exchange",
			method: http.MethodGet,
			path:   testProvider.TokenEndpoint().Relative(),
			values: map[string]string{
				"grant_type": string(protocol.GrantTypeCode),
				"code":       "123",
			},
			wantCode: http.StatusUnauthorized,
			json:     `{"error":"invalid_client"}`,
		},
		{
			name:   "JWT authorization",
			method: http.MethodGet,
			path:   testProvider.TokenEndpoint().Relative(),
			values: map[string]string{
				"grant_type": string(protocol.GrantTypeBearer),
				"scope":      protocol.SpaceDelimitedArray{protocol.ScopeOpenID, protocol.ScopeOfflineAccess}.String(),
				"assertion":  jwtToken,
			},
			wantCode: http.StatusBadRequest,
			json:     "{\"error\":\"invalid_grant\",\"error_description\":\"audience is not valid: Audience must contain client_id \\\"https://localhost:9998/\\\"\"}",
		},
		{
			name:      "Token exchange",
			method:    http.MethodGet,
			path:      testProvider.TokenEndpoint().Relative(),
			basicAuth: &basicAuth{"web", "secret"},
			values: map[string]string{
				"grant_type":         string(protocol.GrantTypeTokenExchange),
				"scope":              protocol.SpaceDelimitedArray{protocol.ScopeOpenID, protocol.ScopeOfflineAccess}.String(),
				"subject_token":      jwtToken,
				"subject_token_type": string(protocol.AccessTokenType),
			},
			wantCode: http.StatusOK,
			contains: []string{
				`{"access_token":"`,
				`"issued_token_type":"urn:ietf:params:oauth:token-type:refresh_token","token_type":"Bearer","expires_in":`,
				`,"scope":"openid offline_access","refresh_token":"`,
			},
			expiresIn: 300,
		},
		{
			name:      "Client credentials exchange",
			method:    http.MethodGet,
			path:      testProvider.TokenEndpoint().Relative(),
			basicAuth: &basicAuth{"sid1", "verysecret"},
			values: map[string]string{
				"grant_type": string(protocol.GrantTypeClientCredentials),
				"scope":      protocol.SpaceDelimitedArray{protocol.ScopeOpenID, protocol.ScopeOfflineAccess}.String(),
			},
			wantCode:  http.StatusOK,
			contains:  []string{`{"access_token":"`, `"token_type":"Bearer","expires_in":`, `,"scope":"openid offline_access"}`},
			expiresIn: 300,
		},
		{
			// This call will fail. A successful test is already
			// part of device_test.go
			name:      "device token",
			method:    http.MethodPost,
			path:      testProvider.TokenEndpoint().Relative(),
			basicAuth: &basicAuth{"web", "secret"},
			header: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: map[string]string{
				"grant_type":  string(protocol.GrantTypeDeviceCode),
				"device_code": "123",
			},
			wantCode: http.StatusBadRequest,
			json:     `{"error":"access_denied","error_description":"The authorization request was denied."}`,
		},
		{
			name:     "missing grant type",
			method:   http.MethodGet,
			path:     testProvider.TokenEndpoint().Relative(),
			wantCode: http.StatusBadRequest,
			json:     `{"error":"invalid_request","error_description":"grant_type missing"}`,
		},
		{
			name:   "unsupported grant type",
			method: http.MethodGet,
			path:   testProvider.TokenEndpoint().Relative(),
			values: map[string]string{
				"grant_type": "foo",
			},
			wantCode: http.StatusBadRequest,
			json:     `{"error":"unsupported_grant_type","error_description":"foo not supported"}`,
		},
		{
			name:      "introspection",
			method:    http.MethodGet,
			path:      testProvider.IntrospectionEndpoint().Relative(),
			basicAuth: &basicAuth{"web", "secret"},
			values: map[string]string{
				"token": accessToken,
			},
			wantCode: http.StatusOK,
			contains: []string{
				`{"active":true,"scope":"openid offline_access email profile phone","client_id":"web","exp":`,
				`,"sub":"id1","username":"test-user@localhost","name":"Test User","given_name":"Test","family_name":"User","locale":"de","preferred_username":"test-user@localhost","email":"test-user@zitadel.ch","email_verified":true}`,
			},
		},
		{
			name:   "user info",
			method: http.MethodGet,
			path:   testProvider.UserinfoEndpoint().Relative(),
			header: map[string]string{
				"authorization": "Bearer " + accessToken,
			},
			wantCode: http.StatusOK,
			json:     `{"sub":"id1","name":"Test User","given_name":"Test","family_name":"User","locale":"de","preferred_username":"test-user@localhost","email":"test-user@zitadel.ch","email_verified":true}`,
		},
		{
			name:   "refresh token",
			method: http.MethodGet,
			path:   testProvider.TokenEndpoint().Relative(),
			values: map[string]string{
				"grant_type":    string(protocol.GrantTypeRefreshToken),
				"refresh_token": refreshToken,
				"client_id":     client.GetID(),
				"client_secret": "secret",
			},
			wantCode: http.StatusOK,
			contains: []string{
				`{"access_token":"`,
				`"token_type":"Bearer","refresh_token":"`,
				`"expires_in":`,
				`,"id_token":"`,
			},
			expiresIn: 300,
		},
		{
			name:      "revoke",
			method:    http.MethodGet,
			path:      testProvider.RevocationEndpoint().Relative(),
			basicAuth: &basicAuth{"web", "secret"},
			values: map[string]string{
				"token": accessTokenRevoke,
			},
			wantCode: http.StatusOK,
		},
		{
			name:   "end session",
			method: http.MethodGet,
			path:   testProvider.EndSessionEndpoint().Relative(),
			values: map[string]string{
				"id_token_hint": idToken,
				"client_id":     "web",
			},
			wantCode:       http.StatusFound,
			headerContains: map[string]string{"Location": "/logged-out"},
			contains:       []string{`<a href="/logged-out">Found</a>.`},
		},
		{
			name:     "keys",
			method:   http.MethodGet,
			path:     testProvider.KeysEndpoint().Relative(),
			wantCode: http.StatusOK,
			contains: []string{
				`{"keys":[{"alg":"RS256","e":"AQAB","kid":"`,
				`","kty":"RSA","n":"`, `","use":"sig"}`,
				`"alg":"SGD_SM3_SM2","crv":"SM2-P-256"`,
				`"kty":"EC"`,
			},
		},
		{
			name:      "device authorization",
			method:    http.MethodGet,
			path:      testProvider.DeviceAuthorizationEndpoint().Relative(),
			basicAuth: &basicAuth{"device", "secret"},
			values: map[string]string{
				"scope": protocol.SpaceDelimitedArray{protocol.ScopeOpenID, protocol.ScopeOfflineAccess}.String(),
			},
			wantCode: http.StatusOK,
			contains: []string{
				`{"device_code":"`, `","user_code":"`,
				`","verification_uri":"https://localhost:9998/device"`,
				`"verification_uri_complete":"https://localhost:9998/device?user_code=`,
				`"expires_in":`,
				`,"interval":5}`,
			},
			expiresIn: 300,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := gu.PtrCopy(serverURL)
			u.Path = tt.path
			if tt.values != nil {
				u.RawQuery = mapAsValues(tt.values)
			}
			var body io.Reader
			if tt.body != nil {
				body = strings.NewReader(mapAsValues(tt.body))
			}

			req := httptest.NewRequest(tt.method, u.String(), body)
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			if tt.basicAuth != nil {
				req.SetBasicAuth(tt.basicAuth.username, tt.basicAuth.password)
			}

			rec := httptest.NewRecorder()
			testProvider.ServeHTTP(rec, req)

			resp := rec.Result()
			require.NoError(t, err)
			assert.Equal(t, tt.wantCode, resp.StatusCode)

			respBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			respBodyString := string(respBody)
			t.Log(respBodyString)
			t.Log(resp.Header)

			if tt.json != "" {
				assert.JSONEq(t, tt.json, respBodyString)
			}
			for _, c := range tt.contains {
				assert.Contains(t, respBodyString, c)
			}
			if tt.expiresIn > 0 {
				var wrapper struct {
					ExpiresIn uint64 `json:"expires_in"`
				}
				require.NoError(t, json.Unmarshal(respBody, &wrapper))
				assert.InDelta(t, tt.expiresIn, wrapper.ExpiresIn, 2)
			}
			for k, v := range tt.headerContains {
				assert.Contains(t, resp.Header.Get(k), v)
			}
		})
	}
}

func TestWithCustomEndpoints(t *testing.T) {
	type args struct {
		auth       *protocol.Endpoint
		token      *protocol.Endpoint
		userInfo   *protocol.Endpoint
		revocation *protocol.Endpoint
		endSession *protocol.Endpoint
		keys       *protocol.Endpoint
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "all nil",
			args:    args{},
			wantErr: op.ErrNilEndpoint,
		},
		{
			name: "all set",
			args: args{
				auth:       protocol.NewEndpoint("/authorize"),
				token:      protocol.NewEndpoint("/oauth/token"),
				userInfo:   protocol.NewEndpoint("/userinfo"),
				revocation: protocol.NewEndpoint("/revoke"),
				endSession: protocol.NewEndpoint("/end_session"),
				keys:       protocol.NewEndpoint("/keys"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := op.NewProvider(testConfig,
				storage.NewStorage(storage.NewUserStore(testIssuer)),
				op.StaticIssuer(testIssuer),
				op.WithCustomEndpoints(tt.args.auth, tt.args.token, tt.args.userInfo, tt.args.revocation, tt.args.endSession, tt.args.keys),
			)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantErr != nil {
				return
			}
			assert.Equal(t, tt.args.auth, provider.AuthorizationEndpoint())
			assert.Equal(t, tt.args.token, provider.TokenEndpoint())
			assert.Equal(t, tt.args.userInfo, provider.UserinfoEndpoint())
			assert.Equal(t, tt.args.revocation, provider.RevocationEndpoint())
			assert.Equal(t, tt.args.endSession, provider.EndSessionEndpoint())
			assert.Equal(t, tt.args.keys, provider.KeysEndpoint())
		})
	}
}
