package authorization

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// --- fake implementations ---

type fakeClient struct {
	id            string
	authMethod    protocol.AuthMethod
	loginURL      string
	redirectURIs  []string
	appType       ApplicationType
	devMode       bool
	strictScopes  bool
	scopeAllowed  map[string]bool
	responseTypes []protocol.ResponseType
	globPatterns  []string
}

func (c *fakeClient) GetID() string { return c.id }
func (c *fakeClient) AuthMethod() protocol.AuthMethod {
	if c.authMethod == "" {
		return protocol.AuthMethodNone
	}
	return c.authMethod
}
func (c *fakeClient) LoginURL(id string) string        { return c.loginURL + "?id=" + id }
func (c *fakeClient) RedirectURIs() []string           { return c.redirectURIs }
func (c *fakeClient) ApplicationType() ApplicationType { return c.appType }
func (c *fakeClient) DevMode() bool                    { return c.devMode }
func (c *fakeClient) StrictScopeValidation() bool      { return c.strictScopes }
func (c *fakeClient) IsScopeAllowed(scope string) bool {
	if c.scopeAllowed == nil {
		return false
	}
	return c.scopeAllowed[scope]
}
func (c *fakeClient) ResponseTypes() []protocol.ResponseType { return c.responseTypes }
func (c *fakeClient) RedirectURIGlobs() []string             { return c.globPatterns }
func (c *fakeClient) GetSessionState() string                { return "" }

// Ensure fakeClient implements all optional interfaces.
var _ SessionStateClient = (*fakeClient)(nil)
var _ RedirectURIClient = (*fakeClient)(nil)
var _ RedirectURIGlobClient = (*fakeClient)(nil)
var _ ApplicationTypeClient = (*fakeClient)(nil)
var _ DevModeClient = (*fakeClient)(nil)
var _ storm.ScopeValidationClient = (*fakeClient)(nil)

// --- scope validation tests ---

func TestValidateScopes_Lenient(t *testing.T) {
	client := &fakeClient{
		scopeAllowed: map[string]bool{"custom:read": true},
	}
	authReq := &protocol.AuthRequest{
		Scopes: []string{"openid", "profile", "unknown", "custom:read"},
	}

	err := validateScopes(client, authReq)
	require.NoError(t, err)
	assert.Equal(t, protocol.SpaceDelimitedArray{"openid", "profile", "custom:read"}, authReq.Scopes)
}

func TestValidateScopes_Strict(t *testing.T) {
	client := &fakeClient{
		strictScopes: true,
		scopeAllowed: map[string]bool{"profile": true, "custom:read": true},
	}
	authReq := &protocol.AuthRequest{
		Scopes: []string{"openid", "profile", "unknown"},
	}

	err := validateScopes(client, authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope unknown is not allowed")
}

func TestValidateScopes_Empty(t *testing.T) {
	client := &fakeClient{}
	authReq := &protocol.AuthRequest{Scopes: []string{}}

	err := validateScopes(client, authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope is missing")
}

// --- redirect URI validation tests ---

func TestValidateRedirectURI_WebHTTPS(t *testing.T) {
	client := &fakeClient{
		appType:      ApplicationTypeWeb,
		redirectURIs: []string{"https://example.com/callback"},
	}
	err := validateRedirectURI(client, "https://example.com/callback", protocol.ResponseTypeCode)
	require.NoError(t, err)
}

func TestValidateRedirectURI_WebHTTPRejected(t *testing.T) {
	client := &fakeClient{
		appType:      ApplicationTypeWeb,
		redirectURIs: []string{"http://example.com/callback"},
	}
	err := validateRedirectURI(client, "http://example.com/callback", protocol.ResponseTypeCode)
	require.Error(t, err)
}

func TestValidateRedirectURI_WebDevMode(t *testing.T) {
	client := &fakeClient{
		appType:      ApplicationTypeWeb,
		redirectURIs: []string{"http://localhost/callback"},
		devMode:      true,
	}
	err := validateRedirectURI(client, "http://localhost/callback", protocol.ResponseTypeCode)
	require.NoError(t, err)
}

func TestValidateRedirectURI_NativeCustomScheme(t *testing.T) {
	client := &fakeClient{
		appType:      ApplicationTypeNative,
		redirectURIs: []string{"com.example.app:/callback"},
	}
	err := validateRedirectURI(client, "com.example.app:/callback", protocol.ResponseTypeCode)
	require.NoError(t, err)
}

func TestValidateRedirectURI_NativeLoopback(t *testing.T) {
	client := &fakeClient{
		appType:      ApplicationTypeNative,
		redirectURIs: []string{"http://localhost:8080/callback"},
	}
	err := validateRedirectURI(client, "http://127.0.0.1:8080/callback", protocol.ResponseTypeCode)
	require.NoError(t, err)
}

func TestValidateRedirectURI_GlobMatch(t *testing.T) {
	client := &fakeClient{
		appType:      ApplicationTypeWeb,
		redirectURIs: []string{},
		globPatterns: []string{"https://*.example.com/callback"},
	}
	err := validateRedirectURI(client, "https://app.example.com/callback", protocol.ResponseTypeCode)
	require.NoError(t, err)
}

// --- form post response tests ---

func TestWriteFormPostResponse(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &codeResponse{
		Code:  "test-code",
		State: "test-state",
	}

	err := writeFormPostResponse(w, "https://example.com/callback", resp)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "test-code")
	assert.Contains(t, w.Body.String(), "test-state")
	assert.Contains(t, w.Body.String(), `action="https://example.com/callback"`)
}

// --- isLocalhost tests ---

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		host     string
		expected bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", false}, // 0.0.0.0 is wildcard, NOT loopback per RFC 8252 §7.3
		{"192.168.1.1", false},
		{"example.com", false},
		{"[::1]", false}, // brackets not stripped
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			assert.Equal(t, tt.expected, isLocalhost(tt.host))
		})
	}
}

// --- validatePKCE tests ---

func TestValidatePKCE(t *testing.T) {
	tests := []struct {
		name    string
		authReq *protocol.AuthRequest
		wantErr bool
	}{
		{
			name:    "no code_challenge",
			authReq: &protocol.AuthRequest{},
			wantErr: false,
		},
		{
			name:    "S256 method",
			authReq: &protocol.AuthRequest{CodeChallenge: "abc123", CodeChallengeMethod: protocol.CodeChallengeMethodS256},
			wantErr: false,
		},
		{
			name:    "plain method",
			authReq: &protocol.AuthRequest{CodeChallenge: "abc123", CodeChallengeMethod: protocol.CodeChallengeMethodPlain},
			wantErr: false,
		},
		{
			name:    "default method (empty)",
			authReq: &protocol.AuthRequest{CodeChallenge: "abc123", CodeChallengeMethod: ""},
			wantErr: false,
		},
		{
			name:    "unsupported method",
			authReq: &protocol.AuthRequest{CodeChallenge: "abc123", CodeChallengeMethod: "S512"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePKCE(tt.authReq)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- validateNonce tests ---

func TestValidateNonce_ImplicitFlow(t *testing.T) {
	tests := []struct {
		name    string
		authReq *protocol.AuthRequest
		wantErr bool
	}{
		{
			name:    "code flow no nonce ok",
			authReq: &protocol.AuthRequest{ResponseType: protocol.ResponseTypeCode},
			wantErr: false,
		},
		{
			name:    "id_token without nonce fails",
			authReq: &protocol.AuthRequest{ResponseType: protocol.ResponseTypeIDToken},
			wantErr: true,
		},
		{
			name:    "id_token with nonce ok",
			authReq: &protocol.AuthRequest{ResponseType: protocol.ResponseTypeIDToken, Nonce: "abc"},
			wantErr: false,
		},
		{
			name:    "id_token only without nonce fails",
			authReq: &protocol.AuthRequest{ResponseType: protocol.ResponseTypeIDTokenOnly},
			wantErr: true,
		},
		{
			name:    "id_token only with nonce ok",
			authReq: &protocol.AuthRequest{ResponseType: protocol.ResponseTypeIDTokenOnly, Nonce: "abc"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNonce(tt.authReq)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- validatePrompt tests ---

func TestValidatePrompt(t *testing.T) {
	tests := []struct {
		name    string
		authReq *protocol.AuthRequest
		wantErr bool
		check   func(t *testing.T, req *protocol.AuthRequest)
	}{
		{
			name:    "empty prompt",
			authReq: &protocol.AuthRequest{},
			wantErr: false,
		},
		{
			name:    "prompt=none alone",
			authReq: &protocol.AuthRequest{Prompt: []string{protocol.PromptNone}},
			wantErr: false,
		},
		{
			name:    "prompt=none with login fails",
			authReq: &protocol.AuthRequest{Prompt: []string{protocol.PromptNone, protocol.PromptLogin}},
			wantErr: true,
		},
		{
			name:    "prompt=login sets max_age=0",
			authReq: &protocol.AuthRequest{Prompt: []string{protocol.PromptLogin}},
			wantErr: false,
			check: func(t *testing.T, req *protocol.AuthRequest) {
				require.NotNil(t, req.MaxAge)
				assert.Equal(t, uint(0), *req.MaxAge)
			},
		},
		{
			name:    "prompt=consent alone ok",
			authReq: &protocol.AuthRequest{Prompt: []string{protocol.PromptConsent}},
			wantErr: false,
		},
		{
			name:    "prompt=select_account alone ok",
			authReq: &protocol.AuthRequest{Prompt: []string{protocol.PromptSelectAccount}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePrompt(tt.authReq)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tt.check != nil {
				tt.check(t, tt.authReq)
			}
		})
	}
}

// --- validateResponseType tests ---

func TestValidateResponseType(t *testing.T) {
	tests := []struct {
		name         string
		client       *fakeClient
		responseType protocol.ResponseType
		wantErr      bool
	}{
		{
			name:         "empty response type",
			client:       &fakeClient{},
			responseType: "",
			wantErr:      true,
		},
		{
			name:         "code allowed",
			client:       &fakeClient{responseTypes: []protocol.ResponseType{protocol.ResponseTypeCode}},
			responseType: protocol.ResponseTypeCode,
			wantErr:      false,
		},
		{
			name:         "id_token not allowed",
			client:       &fakeClient{responseTypes: []protocol.ResponseType{protocol.ResponseTypeCode}},
			responseType: protocol.ResponseTypeIDToken,
			wantErr:      true,
		},
		{
			name:         "no response types restriction",
			client:       &fakeClient{responseTypes: nil}, // nil means no restriction
			responseType: protocol.ResponseTypeCode,
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResponseType(tt.client, tt.responseType)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- isImplicitResponseType tests ---

func TestIsImplicitResponseType(t *testing.T) {
	assert.True(t, isImplicitResponseType(protocol.ResponseTypeIDTokenOnly))
	assert.True(t, isImplicitResponseType(protocol.ResponseTypeIDToken))
	assert.False(t, isImplicitResponseType(protocol.ResponseTypeCode))
}

// --- hashTokenForIDToken tests ---

func TestHashTokenForIDToken(t *testing.T) {
	// Test with RS256 (SHA-256)
	// Per OIDC Core §2: at_hash is the base64url encoding of the left-most
	// half of the hash of the octets of the ASCII representation of the access_token value.
	t.Run("RS256 hash", func(t *testing.T) {
		accessToken := "test-access-token-12345"
		hash := hashTokenForIDToken(accessToken, "RS256", nil)
		assert.NotEmpty(t, hash)
		// The hash should be base64url encoded and non-empty
		_, err := base64.RawURLEncoding.DecodeString(hash)
		assert.NoError(t, err, "at_hash should be valid base64url")
	})

	t.Run("same token same hash", func(t *testing.T) {
		accessToken := "consistent-token"
		hash1 := hashTokenForIDToken(accessToken, "RS256", nil)
		hash2 := hashTokenForIDToken(accessToken, "RS256", nil)
		assert.Equal(t, hash1, hash2, "same token should produce same hash")
	})

	t.Run("different tokens different hash", func(t *testing.T) {
		hash1 := hashTokenForIDToken("token-a", "RS256", nil)
		hash2 := hashTokenForIDToken("token-b", "RS256", nil)
		assert.NotEqual(t, hash1, hash2, "different tokens should produce different hashes")
	})

	t.Run("unsupported algorithm returns empty", func(t *testing.T) {
		hash := hashTokenForIDToken("token", "UNKNOWN", nil)
		assert.Empty(t, hash, "unsupported algorithm should return empty string")
	})
}

// --- copyRequestObjectToAuthRequest tests ---

func TestCopyRequestObjectToAuthRequest(t *testing.T) {
	authReq := &protocol.AuthRequest{
		Scopes:       []string{"openid"},
		State:        "original-state",
		Nonce:        "original-nonce",
		RequestParam: "original-jwt",
	}
	requestObject := &protocol.RequestObject{
		AuthRequest: protocol.AuthRequest{
			Scopes:      []string{"openid", "profile"},
			State:       "new-state",
			Nonce:       "new-nonce",
			RedirectURI: "https://example.com/new-callback",
		},
	}

	copyRequestObjectToAuthRequest(authReq, requestObject)

	assert.Equal(t, protocol.SpaceDelimitedArray{"openid", "profile"}, authReq.Scopes)
	assert.Equal(t, "new-state", authReq.State)
	assert.Equal(t, "new-nonce", authReq.Nonce)
	assert.Equal(t, "https://example.com/new-callback", authReq.RedirectURI)
	assert.Empty(t, authReq.RequestParam) // RequestParam should be cleared
}

func TestCopyRequestObjectToAuthRequest_EmptyScopesNotOverwritten(t *testing.T) {
	authReq := &protocol.AuthRequest{
		Scopes: []string{"openid", "profile"},
	}
	requestObject := &protocol.RequestObject{
		AuthRequest: protocol.AuthRequest{
			// Scopes is empty, should not overwrite
			State: "new-state",
		},
	}

	copyRequestObjectToAuthRequest(authReq, requestObject)

	// Scopes should remain unchanged since request object has no scopes
	assert.Equal(t, protocol.SpaceDelimitedArray{"openid", "profile"}, authReq.Scopes)
	assert.Equal(t, "new-state", authReq.State)
}

// --- writeAuthError tests ---

func TestWriteAuthError_QueryMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	writeAuthError(w, r, "https://example.com/callback", "test-state", protocol.ResponseModeQuery,
		protocol.ErrAccessDenied())

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "error=access_denied")
	assert.Contains(t, location, "state=test-state")
	assert.Contains(t, location, "https://example.com/callback?")
}

func TestWriteAuthError_FragmentMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	writeAuthError(w, r, "https://example.com/callback#existing=fragment", "test-state", protocol.ResponseModeFragment,
		protocol.ErrAccessDenied())

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	// Fragment parameters are encoded in the URL fragment
	assert.Contains(t, location, "error=access_denied")
	assert.Contains(t, location, "state=test-state")
}

func TestWriteAuthError_NoRedirectURI(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	writeAuthError(w, r, "", "", protocol.ResponseModeQuery,
		protocol.ErrAccessDenied())

	// Should fall back to JSON error response (400 for access_denied)
	assert.NotEqual(t, http.StatusFound, w.Code)
}

func TestWriteAuthError_FormPostMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	writeAuthError(w, r, "https://example.com/callback", "test-state", protocol.ResponseModeFormPost,
		protocol.ErrAccessDenied())

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "access_denied")
	assert.Contains(t, body, `action="https://example.com/callback"`)
}

// --- httpLoopbackOrLocalhost tests ---

func TestHttpLoopbackOrLocalhost(t *testing.T) {
	tests := []struct {
		url     string
		isLocal bool
	}{
		{"http://localhost/callback", true},
		{"http://127.0.0.1:8080/callback", true},
		{"https://[::1]/callback", true},
		{"http://192.168.1.1/callback", false},
		{"https://example.com/callback", false},
		{"ftp://localhost/file", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			_, ok := httpLoopbackOrLocalhost(tt.url)
			assert.Equal(t, tt.isLocal, ok)
		})
	}
}

// --- validateRedirectURI edge cases ---

func TestValidateRedirectURI_MissingURI(t *testing.T) {
	client := &fakeClient{appType: ApplicationTypeWeb}
	err := validateRedirectURI(client, "", protocol.ResponseTypeCode)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect_uri is missing")
}

func TestValidateRedirectURI_WebLocalhostHTTP(t *testing.T) {
	client := &fakeClient{
		appType:      ApplicationTypeWeb,
		redirectURIs: []string{"http://localhost:8080/callback"},
	}
	err := validateRedirectURI(client, "http://localhost:8080/callback", protocol.ResponseTypeCode)
	require.NoError(t, err)
}

func TestValidateRedirectURI_WebConfidentialClientHTTP(t *testing.T) {
	client := &fakeClient{
		appType:      ApplicationTypeWeb,
		authMethod:   protocol.AuthMethodBasic,
		redirectURIs: []string{"http://example.com/callback"},
	}
	err := validateRedirectURI(client, "http://example.com/callback", protocol.ResponseTypeCode)
	require.NoError(t, err)
}

func TestValidateRedirectURI_NativeNonLoopbackHTTP(t *testing.T) {
	client := &fakeClient{
		appType:      ApplicationTypeNative,
		redirectURIs: []string{"http://example.com/callback"},
	}
	err := validateRedirectURI(client, "http://example.com/callback", protocol.ResponseTypeCode)
	require.Error(t, err)
}

// --- algorithmToJWA tests ---

func TestAlgorithmToJWA(t *testing.T) {
	tests := []struct {
		alg     string
		wantErr bool
	}{
		{"RS256", false},
		{"ES256", false},
		{"PS256", false},
		{"INVALID", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			_, err := algorithmToJWA(tt.alg)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- XSS prevention tests ---

func TestWriteFormPostError_XSSPrevention(t *testing.T) {
	w := httptest.NewRecorder()
	params := url.Values{}
	params.Set("error", "access_denied")
	params.Set("error_description", `<script>alert("xss")</script>`)
	params.Set("state", `" onload="alert(1)`)

	err := writeFormPostError(w, "https://example.com/callback", params)
	require.NoError(t, err)

	body := w.Body.String()
	// Script tags must be escaped
	assert.NotContains(t, body, "<script>")
	assert.Contains(t, body, "&lt;script&gt;")
	// Double quotes in attribute values must be escaped
	assert.NotContains(t, body, `" onload="alert(1)`)
}

func TestWriteFormPostError_JavascriptURI(t *testing.T) {
	w := httptest.NewRecorder()
	params := url.Values{}
	params.Set("error", "access_denied")

	err := writeFormPostError(w, `javascript:alert(1)`, params)
	require.NoError(t, err)

	body := w.Body.String()
	// html/template sanitizes javascript: URIs in action attributes
	assert.NotContains(t, body, "javascript:alert(1)")
}
