package protocol_test

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// AuthRequest.LogValue() tests
// ============================================================================

func TestAuthRequest_LogValue(t *testing.T) {
	tests := []struct {
		name string
		req  *protocol.AuthRequest
		want slog.Value
	}{
		{
			name: "partial fields",
			req: &protocol.AuthRequest{
				Scopes:       protocol.SpaceDelimitedArray{"a", "b"},
				ResponseType: "respType",
				ClientID:     "123",
				RedirectURI:  "http://example.com/callback",
			},
			want: slog.GroupValue(
				slog.Any("scopes", protocol.SpaceDelimitedArray{"a", "b"}),
				slog.String("response_type", "respType"),
				slog.String("client_id", "123"),
				slog.String("redirect_uri", "http://example.com/callback"),
			),
		},
		{
			name: "empty fields",
			req:  &protocol.AuthRequest{},
			want: slog.GroupValue(
				slog.Any("scopes", protocol.SpaceDelimitedArray(nil)),
				slog.String("response_type", ""),
				slog.String("client_id", ""),
				slog.String("redirect_uri", ""),
			),
		},
		{
			name: "all fields populated",
			req: &protocol.AuthRequest{
				Scopes:              protocol.SpaceDelimitedArray{"openid", "profile", "email"},
				ResponseType:        protocol.ResponseTypeCode,
				ClientID:            "client-123",
				RedirectURI:         "https://example.com/callback",
				State:               "state-xyz",
				Nonce:               "nonce-abc",
				ResponseMode:        protocol.ResponseModeFragment,
				Display:             "page",
				Prompt:              protocol.SpaceDelimitedArray{"consent"},
				MaxAge:              uintPtr(3600),
				IDTokenHint:         "eyJhbGciOiJSUzI1NiJ9...",
				LoginHint:           "user@example.com",
				ACRValues:           protocol.SpaceDelimitedArray{"urn:mace:incommon:iap:silver"},
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: protocol.CodeChallengeMethodS256,
				RequestParam:        "eyJhbGciOiJSUzI1NiJ9...",
				RequestURI:          "urn:ietf:params:oauth:request_uri:abc123",
			},
			want: slog.GroupValue(
				slog.Any("scopes", protocol.SpaceDelimitedArray{"openid", "profile", "email"}),
				slog.String("response_type", "code"),
				slog.String("client_id", "client-123"),
				slog.String("redirect_uri", "https://example.com/callback"),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.LogValue()
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// AuthRequest getter methods tests
// ============================================================================

func TestAuthRequest_GetRedirectURI(t *testing.T) {
	tests := []struct {
		name string
		req  *protocol.AuthRequest
		want string
	}{
		{
			name: "with redirect URI",
			req:  &protocol.AuthRequest{RedirectURI: "https://example.com/callback"},
			want: "https://example.com/callback",
		},
		{
			name: "empty redirect URI",
			req:  &protocol.AuthRequest{},
			want: "",
		},
		{
			name: "localhost redirect",
			req:  &protocol.AuthRequest{RedirectURI: "http://localhost:8080/callback"},
			want: "http://localhost:8080/callback",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.GetRedirectURI()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthRequest_GetResponseType(t *testing.T) {
	tests := []struct {
		name string
		req  *protocol.AuthRequest
		want protocol.ResponseType
	}{
		{
			name: "code",
			req:  &protocol.AuthRequest{ResponseType: protocol.ResponseTypeCode},
			want: protocol.ResponseTypeCode,
		},
		{
			name: "id_token token",
			req:  &protocol.AuthRequest{ResponseType: protocol.ResponseTypeIDToken},
			want: protocol.ResponseTypeIDToken,
		},
		{
			name: "id_token only",
			req:  &protocol.AuthRequest{ResponseType: protocol.ResponseTypeIDTokenOnly},
			want: protocol.ResponseTypeIDTokenOnly,
		},
		{
			name: "empty",
			req:  &protocol.AuthRequest{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.GetResponseType()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthRequest_GetState(t *testing.T) {
	tests := []struct {
		name string
		req  *protocol.AuthRequest
		want string
	}{
		{
			name: "with state",
			req:  &protocol.AuthRequest{State: "abc123"},
			want: "abc123",
		},
		{
			name: "empty state",
			req:  &protocol.AuthRequest{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.GetState()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthRequest_GetResponseMode(t *testing.T) {
	tests := []struct {
		name string
		req  *protocol.AuthRequest
		want protocol.ResponseMode
	}{
		{
			name: "query",
			req:  &protocol.AuthRequest{ResponseMode: protocol.ResponseModeQuery},
			want: protocol.ResponseModeQuery,
		},
		{
			name: "fragment",
			req:  &protocol.AuthRequest{ResponseMode: protocol.ResponseModeFragment},
			want: protocol.ResponseModeFragment,
		},
		{
			name: "form_post",
			req:  &protocol.AuthRequest{ResponseMode: protocol.ResponseModeFormPost},
			want: protocol.ResponseModeFormPost,
		},
		{
			name: "empty",
			req:  &protocol.AuthRequest{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.GetResponseMode()
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// PushedAuthResponse JSON tests
// ============================================================================

func TestPushedAuthResponse_JSON(t *testing.T) {
	tests := []struct {
		name    string
		resp    protocol.PushedAuthResponse
		want    string
		wantErr bool
	}{
		{
			name: "standard response",
			resp: protocol.PushedAuthResponse{
				RequestURI: "urn:ietf:params:oauth:request_uri:abc123",
				ExpiresIn:  600,
			},
			want: `{"request_uri":"urn:ietf:params:oauth:request_uri:abc123","expires_in":600}`,
		},
		{
			name: "minimal response",
			resp: protocol.PushedAuthResponse{
				RequestURI: "urn:ietf:params:oauth:request_uri:xyz",
				ExpiresIn:  0,
			},
			want: `{"request_uri":"urn:ietf:params:oauth:request_uri:xyz","expires_in":0}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.resp)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestPushedAuthResponse_JSON_Roundtrip(t *testing.T) {
	original := protocol.PushedAuthResponse{
		RequestURI: "urn:ietf:params:oauth:request_uri:abc123",
		ExpiresIn:  600,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded protocol.PushedAuthResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

// ============================================================================
// Constants verification tests
// ============================================================================

func TestScopeConstants(t *testing.T) {
	assert.Equal(t, "openid", protocol.ScopeOpenID)
	assert.Equal(t, "profile", protocol.ScopeProfile)
	assert.Equal(t, "email", protocol.ScopeEmail)
	assert.Equal(t, "address", protocol.ScopeAddress)
	assert.Equal(t, "phone", protocol.ScopePhone)
	assert.Equal(t, "offline_access", protocol.ScopeOfflineAccess)
}

func TestResponseTypeConstants(t *testing.T) {
	assert.Equal(t, protocol.ResponseType("code"), protocol.ResponseTypeCode)
	assert.Equal(t, protocol.ResponseType("id_token token"), protocol.ResponseTypeIDToken)
	assert.Equal(t, protocol.ResponseType("id_token"), protocol.ResponseTypeIDTokenOnly)
}

func TestResponseModeConstants(t *testing.T) {
	assert.Equal(t, protocol.ResponseMode("query"), protocol.ResponseModeQuery)
	assert.Equal(t, protocol.ResponseMode("fragment"), protocol.ResponseModeFragment)
	assert.Equal(t, protocol.ResponseMode("form_post"), protocol.ResponseModeFormPost)
}

func TestPromptConstants(t *testing.T) {
	assert.Equal(t, "none", protocol.PromptNone)
	assert.Equal(t, "login", protocol.PromptLogin)
	assert.Equal(t, "consent", protocol.PromptConsent)
	assert.Equal(t, "select_account", protocol.PromptSelectAccount)
}

// ============================================================================
// Helper functions
// ============================================================================

func uintPtr(v uint) *uint {
	return &v
}
