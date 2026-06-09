package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// --- fake implementations ---

type fakeClient struct {
	id           string
	authMethod   protocol.AuthMethod
	grantTypes   []protocol.GrantType
	redirectURIs []string
}

func (c *fakeClient) GetID() string                    { return c.id }
func (c *fakeClient) AuthMethod() protocol.AuthMethod  { return c.authMethod }
func (c *fakeClient) LoginURL(id string) string        { return "/login?id=" + id }
func (c *fakeClient) RedirectURIs() []string           { return c.redirectURIs }
func (c *fakeClient) GrantTypes() []protocol.GrantType { return c.grantTypes }

type fakeAuthRequest struct {
	id            string
	clientID      string
	subject       string
	nonce         string
	redirectURI   string
	responseType  protocol.ResponseType
	scopes        []string
	codeChallenge *protocol.CodeChallenge
	authTime      time.Time
	acr           string
	amr           []string
	audience      []string
	sid           string
	extraClaims   map[string]any
	claims        *protocol.ClaimsRequest
}

func (r *fakeAuthRequest) GetID() string                             { return r.id }
func (r *fakeAuthRequest) GetACR() string                            { return r.acr }
func (r *fakeAuthRequest) GetAMR() []string                          { return r.amr }
func (r *fakeAuthRequest) GetAudience() []string                     { return r.audience }
func (r *fakeAuthRequest) GetAuthTime() time.Time                    { return r.authTime }
func (r *fakeAuthRequest) GetClientID() string                       { return r.clientID }
func (r *fakeAuthRequest) GetCodeChallenge() *protocol.CodeChallenge { return r.codeChallenge }
func (r *fakeAuthRequest) GetNonce() string                          { return r.nonce }
func (r *fakeAuthRequest) GetRedirectURI() string                    { return r.redirectURI }
func (r *fakeAuthRequest) GetResponseType() protocol.ResponseType    { return r.responseType }
func (r *fakeAuthRequest) GetResponseMode() protocol.ResponseMode    { return "" }
func (r *fakeAuthRequest) GetScopes() []string                       { return r.scopes }
func (r *fakeAuthRequest) GetState() string                          { return "" }
func (r *fakeAuthRequest) GetSubject() string                        { return r.subject }
func (r *fakeAuthRequest) GetClaims() *protocol.ClaimsRequest        { return r.claims }
func (r *fakeAuthRequest) GetSID() string                            { return r.sid }
func (r *fakeAuthRequest) Done() bool                                { return false }
func (r *fakeAuthRequest) ExtraIDTokenClaims() map[string]any        { return r.extraClaims }

type fakeTokenRequest struct {
	subject  string
	clientID string
	scopes   []string
	audience []string
}

func (r *fakeTokenRequest) GetSubject() string    { return r.subject }
func (r *fakeTokenRequest) GetClientID() string   { return r.clientID }
func (r *fakeTokenRequest) GetScopes() []string   { return r.scopes }
func (r *fakeTokenRequest) GetAudience() []string { return r.audience }

type fakeRefreshReq struct {
	fakeTokenRequest
	id            string
	nonce         string
	authTime      time.Time
	codeChallenge *protocol.CodeChallenge
	amr           []string
}

func (r *fakeRefreshReq) GetID() string                             { return r.id }
func (r *fakeRefreshReq) GetNonce() string                          { return r.nonce }
func (r *fakeRefreshReq) GetAuthTime() time.Time                    { return r.authTime }
func (r *fakeRefreshReq) GetCodeChallenge() *protocol.CodeChallenge { return r.codeChallenge }
func (r *fakeRefreshReq) GetAMR() []string                          { return r.amr }
func (r *fakeRefreshReq) SetCurrentScopes(scopes []string)          { r.fakeTokenRequest.scopes = scopes }

type fakeClientStore struct {
	clients map[string]*fakeClient
}

func (s *fakeClientStore) GetClientByClientID(_ context.Context, clientID string) (storm.Client, error) {
	c, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}
	return c, nil
}

func (s *fakeClientStore) AuthorizeClientIDSecret(_ context.Context, clientID, clientSecret string) error {
	c, ok := s.clients[clientID]
	if !ok {
		return fmt.Errorf("client not found: %s", clientID)
	}
	if c.authMethod == protocol.AuthMethodNone {
		return nil
	}
	if clientSecret == "" {
		return protocol.ErrInvalidClient().WithDescription("client_secret missing")
	}
	// For testing, accept any non-empty secret
	return nil
}

type fakeAuthStore struct {
	authRequests  map[string]*fakeAuthRequest
	byCode        map[string]*fakeAuthRequest
	deleted       []string
	trackedTokens map[string]string // authRequestID -> tokenID
	revokedCodes  map[string]bool
}

func newFakeAuthStore() *fakeAuthStore {
	return &fakeAuthStore{
		authRequests:  make(map[string]*fakeAuthRequest),
		byCode:        make(map[string]*fakeAuthRequest),
		trackedTokens: make(map[string]string),
		revokedCodes:  make(map[string]bool),
	}
}

func (s *fakeAuthStore) CreateAuthRequest(_ context.Context, _ *protocol.AuthRequest, _ string) (storm.AuthRequest, error) {
	return nil, nil
}
func (s *fakeAuthStore) AuthRequestByID(_ context.Context, id string) (storm.AuthRequest, error) {
	req, ok := s.authRequests[id]
	if !ok {
		return nil, fmt.Errorf("auth request not found: %s", id)
	}
	return req, nil
}
func (s *fakeAuthStore) AuthRequestByCode(_ context.Context, code string) (storm.AuthRequest, error) {
	req, ok := s.byCode[code]
	if !ok {
		return nil, fmt.Errorf("code not found or already used: %s", code)
	}
	return req, nil
}
func (s *fakeAuthStore) SaveAuthCode(_ context.Context, _, _ string) error { return nil }
func (s *fakeAuthStore) DeleteAuthRequest(_ context.Context, id string) error {
	s.deleted = append(s.deleted, id)
	// Also remove from byCode so code reuse is detected
	for code, req := range s.byCode {
		if req.id == id {
			delete(s.byCode, code)
			break
		}
	}
	return nil
}

// CodeReuseDetector
func (s *fakeAuthStore) TrackTokenForAuthRequest(authRequestID, tokenID string) {
	s.trackedTokens[authRequestID] = tokenID
}
func (s *fakeAuthStore) RevokeTokensForUsedCode(code string) string {
	s.revokedCodes[code] = true
	return ""
}

type fakeTokenStore struct {
	tokens        map[string]*fakeTokenRequest
	refreshTokens map[string]*fakeRefreshReq
	nextTokenID   string
	nextRefreshID string
}

func newFakeTokenStore() *fakeTokenStore {
	return &fakeTokenStore{
		tokens:        make(map[string]*fakeTokenRequest),
		refreshTokens: make(map[string]*fakeRefreshReq),
		nextTokenID:   "token-1",
		nextRefreshID: "refresh-1",
	}
}

func (s *fakeTokenStore) CreateAccessToken(_ context.Context, req storm.TokenRequest) (string, time.Time, error) {
	id := s.nextTokenID
	s.tokens[id] = &fakeTokenRequest{
		subject:  req.GetSubject(),
		clientID: req.GetClientID(),
		scopes:   req.GetScopes(),
	}
	return id, time.Now().UTC().Add(1 * time.Hour), nil
}

func (s *fakeTokenStore) CreateAccessAndRefreshTokens(_ context.Context, req storm.TokenRequest, _ string) (string, string, time.Time, error) {
	accessTokenID := s.nextTokenID
	refreshTokenID := s.nextRefreshID
	s.tokens[accessTokenID] = &fakeTokenRequest{
		subject:  req.GetSubject(),
		clientID: req.GetClientID(),
		scopes:   req.GetScopes(),
	}
	s.refreshTokens[refreshTokenID] = &fakeRefreshReq{
		fakeTokenRequest: fakeTokenRequest{
			subject:  req.GetSubject(),
			clientID: req.GetClientID(),
			scopes:   req.GetScopes(),
		},
	}
	return accessTokenID, refreshTokenID, time.Now().UTC().Add(1 * time.Hour), nil
}

func (s *fakeTokenStore) TokenRequestByRefreshToken(_ context.Context, refreshToken string) (storm.RefreshTokenRequest, error) {
	req, ok := s.refreshTokens[refreshToken]
	if !ok {
		return nil, fmt.Errorf("refresh token not found: %s", refreshToken)
	}
	return req, nil
}

type fakeSigningKey struct {
	id  string
	alg string
	key jwk.Key
}

func (k *fakeSigningKey) ID() string        { return k.id }
func (k *fakeSigningKey) Algorithm() string { return k.alg }
func (k *fakeSigningKey) Key() jwk.Key      { return k.key }

func mustNewFakeSigningKey(t *testing.T) *fakeSigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import[jwk.Key](priv)
	require.NoError(t, err)
	_ = key.Set(jwk.AlgorithmKey, "ES256")
	_ = key.Set(jwk.KeyIDKey, "test-key")
	return &fakeSigningKey{id: "test-key", alg: "ES256", key: key}
}

type fakeKeyStore struct {
	signingKey *fakeSigningKey
}

func (s *fakeKeyStore) KeySet(_ context.Context) ([]protocol.Key, error) {
	return nil, nil
}
func (s *fakeKeyStore) SignatureAlgorithms(_ context.Context) ([]string, error) {
	if s.signingKey != nil {
		return []string{s.signingKey.alg}, nil
	}
	return []string{"RS256"}, nil
}
func (s *fakeKeyStore) SigningKey(_ context.Context) (storm.SigningKey, error) {
	if s.signingKey == nil {
		return nil, fmt.Errorf("no signing key")
	}
	return s.signingKey, nil
}

type fakeCrypto struct{}

func (c *fakeCrypto) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	result := make([]byte, len(plaintext))
	for i, b := range plaintext {
		result[i] = b ^ 0xFF
	}
	return result, nil
}

func (c *fakeCrypto) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	result := make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		result[i] = b ^ 0xFF
	}
	return result, nil
}

func (c *fakeCrypto) Hash(_ context.Context, _ string, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return h[:], nil
}

func (c *fakeCrypto) Sign(_ context.Context, _ string, _ []byte) (string, error) {
	return "fake-signature", nil
}

func (c *fakeCrypto) AlgorithmSuite() string { return "ECDSA+SHA256+AES" }

func newTestPlugin(t *testing.T, clientStore *fakeClientStore, authStore *fakeAuthStore, tokenStore *fakeTokenStore) *Plugin {
	t.Helper()
	ks := &fakeKeyStore{
		signingKey: mustNewFakeSigningKey(t),
	}
	decoder := protocol.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	return &Plugin{
		tokenStore:  tokenStore,
		clientStore: clientStore,
		authStore:   authStore,
		crypto:      &fakeCrypto{},
		keyStore:    ks,
		decoder:     decoder,
		logger:      slog.Default(),
	}
}

// newTestPluginNoKeyStore creates a plugin without a keyStore (no ID token signing).
func newTestPluginNoKeyStore(t *testing.T, clientStore *fakeClientStore, authStore *fakeAuthStore, tokenStore *fakeTokenStore) *Plugin {
	t.Helper()
	decoder := protocol.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	return &Plugin{
		tokenStore:  tokenStore,
		clientStore: clientStore,
		authStore:   authStore,
		crypto:      &fakeCrypto{},
		decoder:     decoder,
		logger:      slog.Default(),
	}
}

func newTokenForm(grantType string, extra url.Values) url.Values {
	form := url.Values{}
	form.Set("grant_type", grantType)
	for k, vs := range extra {
		for _, v := range vs {
			form.Set(k, v)
		}
	}
	return form
}

func postTokenRequest(form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()
	return r
}

func postTokenRequestWithBasicAuth(form url.Values, clientID, clientSecret string) *http.Request {
	r := postTokenRequest(form)
	r.SetBasicAuth(clientID, clientSecret)
	return r
}

func decodeTokenResponse(t *testing.T, w *httptest.ResponseRecorder) *protocol.AccessTokenResponse {
	t.Helper()
	var resp protocol.AccessTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return &resp
}

func decodeError(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var errResp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	return errResp
}

// parseIDTokenClaims parses the payload of a JWS compact serialization
// without verifying the signature.
func parseIDTokenClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "expected JWS compact format with 3 parts")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	err = json.Unmarshal(payload, &claims)
	require.NoError(t, err)
	return claims
}

// --- grant_type routing tests ---

func TestHandleToken_MissingGrantType(t *testing.T) {
	p := newTestPlugin(t, &fakeClientStore{}, newFakeAuthStore(), newFakeTokenStore())
	w := httptest.NewRecorder()
	r := postTokenRequest(url.Values{})

	p.handleToken(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_request", errResp["error"])
}

func TestHandleToken_UnsupportedGrantType(t *testing.T) {
	p := newTestPlugin(t, &fakeClientStore{}, newFakeAuthStore(), newFakeTokenStore())
	w := httptest.NewRecorder()
	r := postTokenRequest(newTokenForm("unsupported_type", nil))

	p.handleToken(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "unsupported_grant_type", errResp["error"])
}

// --- authorization_code grant tests ---

func TestHandleAuthorizationCode_Success(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["test-code"] = &fakeAuthRequest{
		id:           "auth-req-1",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		scopes:       []string{"openid"},
		responseType: protocol.ResponseTypeCode,
	}
	ts := newFakeTokenStore()

	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"test-code"},
		"redirect_uri": {"https://example.com/callback"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeTokenResponse(t, w)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, protocol.BearerToken, resp.TokenType)
	assert.NotEmpty(t, resp.IDToken)
}

func TestHandleAuthorizationCode_CHashPresent(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["test-code"] = &fakeAuthRequest{
		id:           "auth-req-1",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		scopes:       []string{"openid"},
		responseType: protocol.ResponseTypeCode,
	}
	ts := newFakeTokenStore()

	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"test-code"},
		"redirect_uri": {"https://example.com/callback"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeTokenResponse(t, w)
	assert.NotEmpty(t, resp.IDToken)

	// Parse ID token claims and verify c_hash is present
	claims := parseIDTokenClaims(t, resp.IDToken)
	assert.NotEmpty(t, claims["c_hash"], "c_hash must be present in ID token when authorization code is exchanged")
}

func TestHandleAuthorizationCode_MissingCode(t *testing.T) {
	p := newTestPlugin(t, &fakeClientStore{}, newFakeAuthStore(), newFakeTokenStore())
	w := httptest.NewRecorder()
	r := postTokenRequest(newTokenForm("authorization_code", nil))

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_request", errResp["error"])
	assert.Contains(t, errResp["error_description"], "code is missing")
}

func TestHandleAuthorizationCode_InvalidCode(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic},
		},
	}
	as := newFakeAuthStore()
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"bad-code"},
		"redirect_uri": {"https://example.com/callback"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestHandleAuthorizationCode_ClientMismatch(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic},
			"client2": {id: "client2", authMethod: protocol.AuthMethodBasic},
		},
	}
	as := newFakeAuthStore()
	as.byCode["test-code"] = &fakeAuthRequest{
		id:           "auth-req-1",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		responseType: protocol.ResponseTypeCode,
	}
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"test-code"},
		"redirect_uri": {"https://example.com/callback"},
	})
	// Authenticate as client2, but the code was issued to client1
	r := postTokenRequestWithBasicAuth(form, "client2", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestHandleAuthorizationCode_RedirectURIMismatch(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["test-code"] = &fakeAuthRequest{
		id:           "auth-req-1",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		responseType: protocol.ResponseTypeCode,
	}
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"test-code"},
		"redirect_uri": {"https://evil.com/callback"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_grant", errResp["error"])
	assert.Contains(t, errResp["error_description"], "redirect_uri does not correspond")
}

func TestHandleAuthorizationCode_CodeReuse(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	as := newFakeAuthStore()
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	// First request: successful
	as.byCode["test-code"] = &fakeAuthRequest{
		id:           "auth-req-1",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		scopes:       []string{"openid"},
		responseType: protocol.ResponseTypeCode,
	}

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"test-code"},
		"redirect_uri": {"https://example.com/callback"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()
	p.handleAuthorizationCode(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request with same code: code reuse detected
	// The code was deleted from byCode after first use, so AuthRequestByCode fails
	w2 := httptest.NewRecorder()
	r2 := postTokenRequestWithBasicAuth(form, "client1", "secret")
	p.handleAuthorizationCode(w2, r2)

	assert.Equal(t, http.StatusBadRequest, w2.Code)
	errResp := decodeError(t, w2)
	assert.Equal(t, "invalid_grant", errResp["error"])

	// Verify code reuse detection was triggered
	assert.True(t, as.revokedCodes["test-code"])
}

func TestHandleAuthorizationCode_PKCE_S256_Success(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["pkce-code"] = &fakeAuthRequest{
		id:           "auth-req-pkce",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		scopes:       []string{"openid"},
		responseType: protocol.ResponseTypeCode,
		codeChallenge: &protocol.CodeChallenge{
			Challenge: challenge,
			Method:    protocol.CodeChallengeMethodS256,
		},
	}
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":          {"pkce-code"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleAuthorizationCode_PKCE_S256_Failure(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["pkce-code"] = &fakeAuthRequest{
		id:           "auth-req-pkce",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		responseType: protocol.ResponseTypeCode,
		codeChallenge: &protocol.CodeChallenge{
			Challenge: "correct-challenge",
			Method:    protocol.CodeChallengeMethodS256,
		},
	}
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":          {"pkce-code"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {"wrong-verifier"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_grant", errResp["error"])
	assert.Contains(t, errResp["error_description"], "PKCE verification failed")
}

func TestHandleAuthorizationCode_PKCE_MissingVerifier(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["pkce-code"] = &fakeAuthRequest{
		id:           "auth-req-pkce",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		responseType: protocol.ResponseTypeCode,
		codeChallenge: &protocol.CodeChallenge{
			Challenge: "some-challenge",
			Method:    protocol.CodeChallengeMethodS256,
		},
	}
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"pkce-code"},
		"redirect_uri": {"https://example.com/callback"},
		// no code_verifier
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_grant", errResp["error"])
	assert.Contains(t, errResp["error_description"], "code_verifier required")
}

func TestHandleAuthorizationCode_PKCE_Plain(t *testing.T) {
	verifier := "plain-verifier-value"

	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["pkce-plain"] = &fakeAuthRequest{
		id:           "auth-req-plain",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		scopes:       []string{"openid"},
		responseType: protocol.ResponseTypeCode,
		codeChallenge: &protocol.CodeChallenge{
			Challenge: verifier,
			Method:    protocol.CodeChallengeMethodPlain,
		},
	}
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":          {"pkce-plain"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleAuthorizationCode_RefreshTokenIssued(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode, protocol.GrantTypeRefreshToken}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["code-rt"] = &fakeAuthRequest{
		id:           "auth-req-rt",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		scopes:       []string{"openid", "offline_access"},
		responseType: protocol.ResponseTypeCode,
	}
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"code-rt"},
		"redirect_uri": {"https://example.com/callback"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeTokenResponse(t, w)
	assert.NotEmpty(t, resp.RefreshToken, "should issue refresh token when offline_access scope present")
}

func TestHandleAuthorizationCode_CodeReuseTracking(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["tracked-code"] = &fakeAuthRequest{
		id:           "auth-req-tracked",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		scopes:       []string{"openid"},
		responseType: protocol.ResponseTypeCode,
	}
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"tracked-code"},
		"redirect_uri": {"https://example.com/callback"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	// Verify the token was tracked for code reuse detection
	assert.Equal(t, "token-1", as.trackedTokens["auth-req-tracked"])
}

func TestHandleAuthorizationCode_GrantTypeNotAllowed(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeClientCredentials}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["code-no-grant"] = &fakeAuthRequest{
		id:           "auth-req-no-grant",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		responseType: protocol.ResponseTypeCode,
	}
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"code-no-grant"},
		"redirect_uri": {"https://example.com/callback"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	p.handleAuthorizationCode(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "unauthorized_client", errResp["error"])
}

// --- refresh_token grant tests ---

func TestHandleRefreshToken_Success(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode, protocol.GrantTypeRefreshToken}},
		},
	}
	as := newFakeAuthStore()
	ts := newFakeTokenStore()
	ts.refreshTokens["refresh-1"] = &fakeRefreshReq{
		fakeTokenRequest: fakeTokenRequest{
			subject:  "user1",
			clientID: "client1",
			scopes:   []string{"openid"},
		},
	}
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("refresh_token", url.Values{
		"refresh_token": {"refresh-1"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	r.ParseForm()
	w := httptest.NewRecorder()

	p.handleRefreshToken(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeTokenResponse(t, w)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestHandleRefreshToken_MissingRefreshToken(t *testing.T) {
	p := newTestPlugin(t, &fakeClientStore{}, newFakeAuthStore(), newFakeTokenStore())
	w := httptest.NewRecorder()
	r := postTokenRequestWithBasicAuth(newTokenForm("refresh_token", nil), "client1", "secret")
	r.ParseForm()

	p.handleRefreshToken(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_request", errResp["error"])
	assert.Contains(t, errResp["error_description"], "refresh_token is missing")
}

func TestHandleRefreshToken_InvalidRefreshToken(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeRefreshToken}},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), newFakeTokenStore())

	form := newTokenForm("refresh_token", url.Values{
		"refresh_token": {"invalid-refresh"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	r.ParseForm()
	w := httptest.NewRecorder()

	p.handleRefreshToken(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestHandleRefreshToken_ClientMismatch(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeRefreshToken}},
			"client2": {id: "client2", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeRefreshToken}},
		},
	}
	ts := newFakeTokenStore()
	ts.refreshTokens["refresh-1"] = &fakeRefreshReq{
		fakeTokenRequest: fakeTokenRequest{
			subject:  "user1",
			clientID: "client1",
			scopes:   []string{"openid"},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), ts)

	form := newTokenForm("refresh_token", url.Values{
		"refresh_token": {"refresh-1"},
	})
	// Authenticate as client2 but refresh token belongs to client1
	r := postTokenRequestWithBasicAuth(form, "client2", "secret")
	r.ParseForm()
	w := httptest.NewRecorder()

	p.handleRefreshToken(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestHandleRefreshToken_ScopeSubset(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeRefreshToken}},
		},
	}
	ts := newFakeTokenStore()
	ts.refreshTokens["refresh-1"] = &fakeRefreshReq{
		fakeTokenRequest: fakeTokenRequest{
			subject:  "user1",
			clientID: "client1",
			scopes:   []string{"openid", "profile"},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), ts)

	// Request with scope that is a subset of original
	form := newTokenForm("refresh_token", url.Values{
		"refresh_token": {"refresh-1"},
		"scope":         {"openid"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	r.ParseForm()
	w := httptest.NewRecorder()

	p.handleRefreshToken(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleRefreshToken_ScopeNotSubset(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeRefreshToken}},
		},
	}
	ts := newFakeTokenStore()
	ts.refreshTokens["refresh-1"] = &fakeRefreshReq{
		fakeTokenRequest: fakeTokenRequest{
			subject:  "user1",
			clientID: "client1",
			scopes:   []string{"openid"},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), ts)

	// Request with scope not in original
	form := newTokenForm("refresh_token", url.Values{
		"refresh_token": {"refresh-1"},
		"scope":         {"openid", "admin"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	r.ParseForm()
	w := httptest.NewRecorder()

	p.handleRefreshToken(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_scope", errResp["error"])
}

func TestHandleRefreshToken_GrantTypeNotAllowed(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	ts := newFakeTokenStore()
	ts.refreshTokens["refresh-1"] = &fakeRefreshReq{
		fakeTokenRequest: fakeTokenRequest{
			subject:  "user1",
			clientID: "client1",
			scopes:   []string{"openid"},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), ts)

	form := newTokenForm("refresh_token", url.Values{
		"refresh_token": {"refresh-1"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	r.ParseForm()
	w := httptest.NewRecorder()

	p.handleRefreshToken(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "unauthorized_client", errResp["error"])
}

// --- client authentication tests ---

func TestAuthenticateClient_BasicAuth(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), newFakeTokenStore())

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.SetBasicAuth("client1", "secret")

	client, err := p.authenticateClient(r, "", "")
	require.NoError(t, err)
	assert.Equal(t, "client1", client.GetID())
}

func TestAuthenticateClient_PostBody(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), newFakeTokenStore())

	form := url.Values{}
	form.Set("client_id", "client1")
	form.Set("client_secret", "secret")
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client, err := p.authenticateClient(r, "client1", "secret")
	require.NoError(t, err)
	assert.Equal(t, "client1", client.GetID())
}

func TestAuthenticateClient_BasicAuthTakesPrecedence(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), newFakeTokenStore())

	form := url.Values{}
	form.Set("client_id", "other-client")
	form.Set("client_secret", "other-secret")
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("client1", "secret")

	// formClientID is "other-client", but Basic Auth has "client1"
	client, err := p.authenticateClient(r, "other-client", "other-secret")
	require.NoError(t, err)
	assert.Equal(t, "client1", client.GetID())
}

func TestAuthenticateClient_MissingClientID(t *testing.T) {
	p := newTestPlugin(t, &fakeClientStore{}, newFakeAuthStore(), newFakeTokenStore())

	r := httptest.NewRequest(http.MethodPost, "/token", nil)

	_, err := p.authenticateClient(r, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id missing")
}

func TestAuthenticateClient_ClientNotFound(t *testing.T) {
	p := newTestPlugin(t, &fakeClientStore{}, newFakeAuthStore(), newFakeTokenStore())

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.SetBasicAuth("unknown-client", "secret")

	_, err := p.authenticateClient(r, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client not found")
}

func TestAuthenticateClient_NativeClientNoSecret(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"native1": {id: "native1", authMethod: protocol.AuthMethodNone},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), newFakeTokenStore())

	r := httptest.NewRequest(http.MethodPost, "/token", nil)

	client, err := p.authenticateClient(r, "native1", "")
	require.NoError(t, err)
	assert.Equal(t, "native1", client.GetID())
}

// --- grant type validation tests ---

func TestValidateGrantType_WithProvider(t *testing.T) {
	client := &fakeClient{
		grantTypes: []protocol.GrantType{protocol.GrantTypeCode, protocol.GrantTypeRefreshToken},
	}
	assert.True(t, validateGrantType(client, protocol.GrantTypeCode))
	assert.True(t, validateGrantType(client, protocol.GrantTypeRefreshToken))
	assert.False(t, validateGrantType(client, protocol.GrantTypeClientCredentials))
}

func TestValidateGrantType_WithoutProvider(t *testing.T) {
	// A client that doesn't implement grantTypesProvider
	c := &noGrantTypesClient{id: "minimal"}
	// Default allows authorization_code and refresh_token
	assert.True(t, validateGrantType(c, protocol.GrantTypeCode))
	assert.True(t, validateGrantType(c, protocol.GrantTypeRefreshToken))
	assert.False(t, validateGrantType(c, protocol.GrantTypeClientCredentials))
}

// noGrantTypesClient is a minimal client that doesn't implement GrantTypes()
type noGrantTypesClient struct {
	id         string
	authMethod protocol.AuthMethod
}

func (c *noGrantTypesClient) GetID() string                   { return c.id }
func (c *noGrantTypesClient) AuthMethod() protocol.AuthMethod { return c.authMethod }
func (c *noGrantTypesClient) LoginURL(id string) string       { return "" }

// --- PKCE verification unit tests ---

func TestVerifyPKCE_NoChallenge(t *testing.T) {
	authReq := &fakeAuthRequest{}
	err := verifyPKCE(authReq, "")
	assert.NoError(t, err)
}

func TestVerifyPKCE_S256_Success(t *testing.T) {
	verifier := "test-verifier-123"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authReq := &fakeAuthRequest{
		codeChallenge: &protocol.CodeChallenge{
			Challenge: challenge,
			Method:    protocol.CodeChallengeMethodS256,
		},
	}
	err := verifyPKCE(authReq, verifier)
	assert.NoError(t, err)
}

func TestVerifyPKCE_S256_Failure(t *testing.T) {
	authReq := &fakeAuthRequest{
		codeChallenge: &protocol.CodeChallenge{
			Challenge: "wrong-challenge",
			Method:    protocol.CodeChallengeMethodS256,
		},
	}
	err := verifyPKCE(authReq, "some-verifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PKCE verification failed")
}

func TestVerifyPKCE_Plain_Success(t *testing.T) {
	authReq := &fakeAuthRequest{
		codeChallenge: &protocol.CodeChallenge{
			Challenge: "same-value",
			Method:    protocol.CodeChallengeMethodPlain,
		},
	}
	err := verifyPKCE(authReq, "same-value")
	assert.NoError(t, err)
}

func TestVerifyPKCE_Plain_Failure(t *testing.T) {
	authReq := &fakeAuthRequest{
		codeChallenge: &protocol.CodeChallenge{
			Challenge: "expected",
			Method:    protocol.CodeChallengeMethodPlain,
		},
	}
	err := verifyPKCE(authReq, "different")
	assert.Error(t, err)
}

func TestVerifyPKCE_UnsupportedMethod(t *testing.T) {
	authReq := &fakeAuthRequest{
		codeChallenge: &protocol.CodeChallenge{
			Challenge: "challenge",
			Method:    "unsupported",
		},
	}
	err := verifyPKCE(authReq, "verifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported code_challenge_method")
}

func TestVerifyPKCE_MissingVerifier(t *testing.T) {
	authReq := &fakeAuthRequest{
		codeChallenge: &protocol.CodeChallenge{
			Challenge: "challenge",
			Method:    protocol.CodeChallengeMethodS256,
		},
	}
	err := verifyPKCE(authReq, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "code_verifier required")
}

// --- refresh scope validation tests ---

func TestValidateRefreshScopes_NoRequestedScopes(t *testing.T) {
	refreshReq := &fakeRefreshReq{
		fakeTokenRequest: fakeTokenRequest{scopes: []string{"openid", "profile"}},
	}
	err := validateRefreshScopes(nil, refreshReq)
	assert.NoError(t, err)
}

func TestValidateRefreshScopes_ValidSubset(t *testing.T) {
	refreshReq := &fakeRefreshReq{
		fakeTokenRequest: fakeTokenRequest{scopes: []string{"openid", "profile", "email"}},
	}
	err := validateRefreshScopes([]string{"openid"}, refreshReq)
	assert.NoError(t, err)
}

func TestValidateRefreshScopes_InvalidScope(t *testing.T) {
	refreshReq := &fakeRefreshReq{
		fakeTokenRequest: fakeTokenRequest{scopes: []string{"openid"}},
	}
	err := validateRefreshScopes([]string{"openid", "admin"}, refreshReq)
	assert.Error(t, err)
}

// --- token exchange tests ---

func TestHandleTokenExchange_MissingSubjectToken(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), newFakeTokenStore())
	w := httptest.NewRecorder()

	form := newTokenForm("urn:ietf:params:oauth:grant-type:token-exchange", url.Values{
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	r.ParseForm()

	p.handleTokenExchange(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_request", errResp["error"])
	assert.Contains(t, errResp["error_description"], "subject_token missing")
}

func TestHandleTokenExchange_MissingSubjectTokenType(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic},
		},
	}
	p := newTestPlugin(t, cs, newFakeAuthStore(), newFakeTokenStore())
	w := httptest.NewRecorder()

	form := newTokenForm("urn:ietf:params:oauth:grant-type:token-exchange", url.Values{
		"subject_token": {"some-token"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	r.ParseForm()

	p.handleTokenExchange(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_request", errResp["error"])
	assert.Contains(t, errResp["error_description"], "subject_token_type missing")
}

// --- token error response tests ---

func TestTokenError_InvalidClient(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/token", nil)

	tokenError(w, r, protocol.ErrInvalidClient())

	// ErrInvalidClient status depends on shared.WriteError mapping
	assert.True(t, w.Code >= 400 && w.Code < 500, "expected 4xx status, got %d", w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_client", errResp["error"])
}

func TestTokenError_InvalidGrant(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/token", nil)

	tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("test error"))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	errResp := decodeError(t, w)
	assert.Equal(t, "invalid_grant", errResp["error"])
	assert.Equal(t, "test error", errResp["error_description"])
}

// --- cache-control header tests ---

func TestTokenResponse_CacheControlHeaders(t *testing.T) {
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", authMethod: protocol.AuthMethodBasic, grantTypes: []protocol.GrantType{protocol.GrantTypeCode}},
		},
	}
	as := newFakeAuthStore()
	as.byCode["cache-test"] = &fakeAuthRequest{
		id:           "auth-req-cache",
		clientID:     "client1",
		subject:      "user1",
		redirectURI:  "https://example.com/callback",
		scopes:       []string{"openid"},
		responseType: protocol.ResponseTypeCode,
	}
	ts := newFakeTokenStore()
	p := newTestPlugin(t, cs, as, ts)

	form := newTokenForm("authorization_code", url.Values{
		"code":         {"cache-test"},
		"redirect_uri": {"https://example.com/callback"},
	})
	r := postTokenRequestWithBasicAuth(form, "client1", "secret")
	w := httptest.NewRecorder()

	// Use handleToken which calls r.ParseForm() before dispatching
	p.handleToken(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
}

// --- getNonce helper tests ---

func TestGetNonce_WithNonceProvider(t *testing.T) {
	req := &fakeAuthRequest{nonce: "test-nonce"}
	assert.Equal(t, "test-nonce", getNonce(req))
}

func TestGetNonce_WithoutNonceProvider(t *testing.T) {
	req := &fakeTokenRequest{subject: "user1"}
	assert.Equal(t, "", getNonce(req))
}

// --- hashToken tests ---

func TestHashToken_ValidAlgorithm(t *testing.T) {
	hash := hashToken("test-token", "ES256")
	assert.NotEmpty(t, hash)
}

func TestHashToken_InvalidAlgorithm(t *testing.T) {
	hash := hashToken("test-token", "INVALID")
	assert.Empty(t, hash)
}

// --- plugin metadata tests ---

func TestPlugin_Name(t *testing.T) {
	p := newTestPlugin(t, &fakeClientStore{}, newFakeAuthStore(), newFakeTokenStore())
	assert.Equal(t, "token", p.Name())
}

func TestPlugin_Category(t *testing.T) {
	p := newTestPlugin(t, &fakeClientStore{}, newFakeAuthStore(), newFakeTokenStore())
	assert.Equal(t, storm.CategoryCore, p.Category())
}

func TestPlugin_Requires(t *testing.T) {
	p := newTestPlugin(t, &fakeClientStore{}, newFakeAuthStore(), newFakeTokenStore())
	requires := p.Requires()
	assert.Contains(t, requires, "TokenStore")
	assert.Contains(t, requires, "AuthStore")
	assert.Contains(t, requires, "ClientStore")
	assert.Contains(t, requires, "KeyStore")
}

func TestPlugin_Contribute(t *testing.T) {
	p := newTestPlugin(t, &fakeClientStore{}, newFakeAuthStore(), newFakeTokenStore())
	ctx := sharedIssuerContext("https://example.com/")
	cfg := &protocol.DiscoveryConfiguration{}
	p.Contribute(ctx, cfg)

	assert.Equal(t, "https://example.com/token", cfg.TokenEndpoint)
	assert.Contains(t, cfg.GrantTypesSupported, "client_credentials")
	assert.Contains(t, cfg.GrantTypesSupported, "refresh_token")
	assert.Contains(t, cfg.TokenEndpointAuthMethodsSupported, "client_secret_basic")
	assert.Contains(t, cfg.TokenEndpointAuthMethodsSupported, "client_secret_post")
}

func sharedIssuerContext(issuer string) context.Context {
	return protocol.ContextWithIssuer(context.Background(), issuer)
}
