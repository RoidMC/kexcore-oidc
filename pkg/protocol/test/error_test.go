package protocol_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

func TestErrorConstructors(t *testing.T) {
	tests := []struct {
		name         string
		constructor  func() *protocol.Error
		expectedType string
		hasDesc      bool
	}{
		{name: "ErrInvalidRequest", constructor: protocol.ErrInvalidRequest, expectedType: "invalid_request"},
		{name: "ErrInvalidRequestRedirectURI", constructor: protocol.ErrInvalidRequestRedirectURI, expectedType: "invalid_request"},
		{name: "ErrInvalidClient", constructor: protocol.ErrInvalidClient, expectedType: "invalid_client"},
		{name: "ErrInvalidGrant", constructor: protocol.ErrInvalidGrant, expectedType: "invalid_grant"},
		{name: "ErrUnauthorizedClient", constructor: protocol.ErrUnauthorizedClient, expectedType: "unauthorized_client"},
		{name: "ErrUnsupportedGrantType", constructor: protocol.ErrUnsupportedGrantType, expectedType: "unsupported_grant_type"},
		{name: "ErrInvalidScope", constructor: protocol.ErrInvalidScope, expectedType: "invalid_scope"},
		{name: "ErrServerError", constructor: protocol.ErrServerError, expectedType: "server_error"},
		{name: "ErrAccessDenied", constructor: protocol.ErrAccessDenied, expectedType: "access_denied", hasDesc: true},
		{name: "ErrUnsupportedResponseType", constructor: protocol.ErrUnsupportedResponseType, expectedType: "unsupported_response_type"},
		{name: "ErrInteractionRequired", constructor: protocol.ErrInteractionRequired, expectedType: "interaction_required"},
		{name: "ErrLoginRequired", constructor: protocol.ErrLoginRequired, expectedType: "login_required"},
		{name: "ErrAccountSelectionRequired", constructor: protocol.ErrAccountSelectionRequired, expectedType: "account_selection_required"},
		{name: "ErrConsentRequired", constructor: protocol.ErrConsentRequired, expectedType: "consent_required"},
		{name: "ErrRegistrationNotSupported", constructor: protocol.ErrRegistrationNotSupported, expectedType: "registration_not_supported"},
		{name: "ErrRequestNotSupported", constructor: protocol.ErrRequestNotSupported, expectedType: "request_not_supported"},
		{name: "ErrRequestURINotSupported", constructor: protocol.ErrRequestURINotSupported, expectedType: "request_uri_not_supported"},
		{name: "ErrAuthorizationPending", constructor: protocol.ErrAuthorizationPending, expectedType: "authorization_pending", hasDesc: true},
		{name: "ErrSlowDown", constructor: protocol.ErrSlowDown, expectedType: "slow_down", hasDesc: true},
		{name: "ErrExpiredDeviceCode", constructor: protocol.ErrExpiredDeviceCode, expectedType: "expired_token", hasDesc: true},
		{name: "ErrInvalidTarget", constructor: protocol.ErrInvalidTarget, expectedType: "invalid_target", hasDesc: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.constructor()

			errJSON, err := json.Marshal(e)
			require.NoError(t, err)

			var m map[string]string
			require.NoError(t, json.Unmarshal(errJSON, &m))

			assert.Equal(t, tt.expectedType, m["error"])
			if tt.hasDesc {
				assert.NotEmpty(t, m["error_description"])
			}

			assert.True(t, e.IsRedirectDisabled() == (tt.name == "ErrInvalidRequestRedirectURI"),
				"only ErrInvalidRequestRedirectURI should have IsRedirectDisabled() == true")
		})
	}
}

func TestError_WithDescription(t *testing.T) {
	tests := []struct {
		name string
		desc string
		args []any
		want string
	}{
		{name: "plain", desc: "something went wrong", want: "something went wrong"},
		{name: "format", desc: "user %s not found", args: []any{"alice"}, want: "user alice not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := protocol.ErrInvalidRequest().WithDescription(tt.desc, tt.args...)
			assert.Equal(t, tt.want, getDescription(t, e))
		})
	}
}

func TestError_WithParent(t *testing.T) {
	parent := errors.New("root cause")
	e := protocol.ErrServerError().WithParent(parent)
	assert.Equal(t, parent, errors.Unwrap(e))
}

func TestError_WithReturnParentToClient(t *testing.T) {
	e := protocol.ErrServerError().WithParent(errors.New("db error")).WithReturnParentToClient(true)
	b, err := json.Marshal(e)
	require.NoError(t, err)

	var m map[string]string
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, "db error", m["parent"])
}

func TestError_IsRedirectDisabled(t *testing.T) {
	assert.True(t, protocol.ErrInvalidRequestRedirectURI().IsRedirectDisabled())
	assert.False(t, protocol.ErrInvalidRequest().IsRedirectDisabled())
	assert.False(t, protocol.ErrServerError().IsRedirectDisabled())
}

func TestError_Error(t *testing.T) {
	tests := []struct {
		name string
		e    *protocol.Error
		want string
	}{
		{
			name: "type only",
			e:    protocol.ErrInvalidRequest(),
			want: "ErrorType=invalid_request",
		},
		{
			name: "with description",
			e:    protocol.ErrInvalidRequest().WithDescription("missing client_id"),
			want: "ErrorType=invalid_request Description=missing client_id",
		},
		{
			name: "with parent",
			e:    protocol.ErrServerError().WithParent(errors.New("db timeout")),
			want: "ErrorType=server_error Parent=db timeout",
		},
		{
			name: "full",
			e:    protocol.ErrInvalidRequest().WithDescription("bad param").WithParent(errors.New("parse error")),
			want: "ErrorType=invalid_request Description=bad param Parent=parse error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.e.Error())
		})
	}
}

func TestError_Is(t *testing.T) {
	a := protocol.ErrInvalidRequest().WithDescription("oops")
	b := protocol.ErrInvalidRequest().WithDescription("oops")
	c := protocol.ErrInvalidRequest().WithDescription("other")
	d := protocol.ErrInvalidClient()

	assert.True(t, errors.Is(a, b))
	assert.False(t, errors.Is(a, c))
	assert.False(t, errors.Is(a, d))

	target := protocol.ErrInvalidRequest().WithDescription("specific").WithReturnParentToClient(true)
	match := protocol.ErrInvalidRequest().WithDescription("specific").WithReturnParentToClient(true)
	assert.True(t, errors.Is(target, match))
}

func TestError_Unwrap(t *testing.T) {
	parent := errors.New("root")
	e := protocol.ErrServerError().WithParent(parent)
	assert.True(t, errors.Is(e, parent))
}

func TestError_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		e    *protocol.Error
		want string
	}{
		{
			name: "simple error",
			e:    protocol.ErrAccessDenied(),
			want: `{"error":"access_denied","error_description":"The authorization request was denied."}`,
		},
		{
			name: "with custom description",
			e:    protocol.ErrAccessDenied().WithDescription("nope"),
			want: `{"error":"access_denied","error_description":"nope"}`,
		},
		{
			name: "without description",
			e:    protocol.ErrInvalidRequest(),
			want: `{"error":"invalid_request"}`,
		},
		{
			name: "with parent not returned",
			e:    protocol.ErrServerError().WithParent(errors.New("db error")),
			want: `{"error":"server_error"}`,
		},
		{
			name: "with parent returned",
			e:    protocol.ErrServerError().WithParent(errors.New("db error")).WithReturnParentToClient(true),
			want: `{"error":"server_error","parent":"db error"}`,
		},
		{
			name: "with state and session_state",
			e: func() *protocol.Error {
				e := protocol.ErrInvalidRequest()
				e.State = "abc"
				e.SessionState = "def"
				return e
			}(),
			want: `{"error":"invalid_request","state":"abc","session_state":"def"}`,
		},
		{
			name: "nil parent with return",
			e:    protocol.ErrServerError().WithReturnParentToClient(true),
			want: `{"error":"server_error"}`,
		},
		{
			name: "device auth pending",
			e:    protocol.ErrAuthorizationPending(),
			want: `{"error":"authorization_pending","error_description":"The client SHOULD repeat the access token request to the token endpoint, after interval from device authorization response."}`,
		},
		{
			name: "slow_down",
			e:    protocol.ErrSlowDown(),
			want: `{"error":"slow_down","error_description":"Polling should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests."}`,
		},
		{
			name: "expired device code",
			e:    protocol.ErrExpiredDeviceCode(),
			want: `{"error":"expired_token","error_description":"The \"device_code\" has expired."}`,
		},
		{
			name: "invalid target",
			e:    protocol.ErrInvalidTarget(),
			want: `{"error":"invalid_target","error_description":"The requested audience or target is invalid."}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.e)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestError_LogLevel(t *testing.T) {
	tests := []struct {
		name string
		e    *protocol.Error
		want slog.Level
	}{
		{name: "server error", e: protocol.ErrServerError(), want: slog.LevelError},
		{name: "authorization pending", e: protocol.ErrAuthorizationPending(), want: slog.LevelInfo},
		{name: "access denied", e: protocol.ErrAccessDenied(), want: slog.LevelWarn},
		{name: "invalid request", e: protocol.ErrInvalidRequest(), want: slog.LevelWarn},
		{name: "invalid grant", e: protocol.ErrInvalidGrant(), want: slog.LevelWarn},
		{name: "slow down", e: protocol.ErrSlowDown(), want: slog.LevelWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.e.LogLevel())
		})
	}
}

func TestError_LogValue(t *testing.T) {
	tests := []struct {
		name string
		e    *protocol.Error
		want slog.Value
	}{
		{
			name: "parent only",
			e:    protocol.ErrServerError().WithParent(io.EOF),
			want: slog.GroupValue(slog.Any("parent", io.EOF), slog.String("type", "server_error")),
		},
		{
			name: "description only",
			e: func() *protocol.Error {
				e := protocol.ErrInvalidRequest()
				e.Description = "oops"
				return e
			}(),
			want: slog.GroupValue(slog.String("description", "oops"), slog.String("type", "invalid_request")),
		},
		{
			name: "state and session_state",
			e: func() *protocol.Error {
				e := protocol.ErrInvalidRequest()
				e.State = "st1"
				e.SessionState = "ss1"
				return e
			}(),
			want: slog.GroupValue(
				slog.String("type", "invalid_request"),
				slog.String("state", "st1"),
				slog.String("session_state", "ss1"),
			),
		},
		{
			name: "all fields",
			e: func() *protocol.Error {
				e := protocol.ErrInvalidGrant().WithParent(io.EOF).WithDescription("bad grant")
				e.State = "s"
				e.SessionState = "ss"
				return e
			}(),
			want: slog.GroupValue(
				slog.Any("parent", io.EOF),
				slog.String("description", "bad grant"),
				slog.String("type", "invalid_grant"),
				slog.String("state", "s"),
				slog.String("session_state", "ss"),
			),
		},
		{
			name: "redirect disabled",
			e:    protocol.ErrInvalidRequestRedirectURI(),
			want: slog.GroupValue(slog.String("type", "invalid_request"), slog.Bool("redirect_disabled", true)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.e.LogValue())
		})
	}
}

func TestDefaultToServerError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		description string
		check       func(t *testing.T, got *protocol.Error)
	}{
		{
			name:        "already *Error is cloned",
			err:         protocol.ErrAccessDenied(),
			description: "should be ignored",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"access_denied","error_description":"The authorization request was denied."}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "already *Error with parent is cloned unchanged",
			err:         protocol.ErrInvalidRequest().WithDescription("custom desc"),
			description: "should be ignored",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"invalid_request","error_description":"custom desc"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "ErrParse maps to invalid_request",
			err:         fmt.Errorf("%w: parse error", protocol.ErrParse),
			description: "parse error",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"invalid_request","error_description":"parse error"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "ErrIssuerInvalid maps to invalid_grant",
			err:         protocol.ErrIssuerInvalid,
			description: "issuer mismatch",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"invalid_grant","error_description":"issuer mismatch"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "ErrExpired maps to invalid_grant",
			err:         protocol.ErrExpired,
			description: "token expired",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"invalid_grant","error_description":"token expired"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "ErrSignatureInvalid maps to invalid_grant",
			err:         protocol.ErrSignatureInvalid,
			description: "bad signature",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"invalid_grant","error_description":"bad signature"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "ErrAudience maps to invalid_grant",
			err:         protocol.ErrAudience,
			description: "wrong aud",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"invalid_grant","error_description":"wrong aud"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "ErrNonceInvalid maps to invalid_grant",
			err:         protocol.ErrNonceInvalid,
			description: "nonce mismatch",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"invalid_grant","error_description":"nonce mismatch"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "ErrAzpMissing maps to invalid_grant",
			err:         protocol.ErrAzpMissing,
			description: "azp missing",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"invalid_grant","error_description":"azp missing"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "ErrAuthTimeNotPresent maps to invalid_grant",
			err:         protocol.ErrAuthTimeNotPresent,
			description: "auth_time missing",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"invalid_grant","error_description":"auth_time missing"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "ErrAtHash maps to invalid_grant",
			err:         protocol.ErrAtHash,
			description: "at_hash wrong",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"invalid_grant","error_description":"at_hash wrong"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "unknown error maps to server_error",
			err:         io.ErrClosedPipe,
			description: "pipe closed",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"server_error","error_description":"pipe closed"}`,
					mustMarshal(t, got),
				)
			},
		},
		{
			name:        "generic error maps to server_error",
			err:         errors.New("unknown"),
			description: "something",
			check: func(t *testing.T, got *protocol.Error) {
				assert.JSONEq(t,
					`{"error":"server_error","error_description":"something"}`,
					mustMarshal(t, got),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.DefaultToServerError(tt.err, tt.description)
			tt.check(t, got)
		})
	}
}

func TestDefaultToServerError_AllVerifierErrors(t *testing.T) {
	invalidGrantErrors := []error{
		protocol.ErrIssuerInvalid,
		protocol.ErrSubjectMissing,
		protocol.ErrAudience,
		protocol.ErrAzpMissing,
		protocol.ErrAzpInvalid,
		protocol.ErrSignatureMissing,
		protocol.ErrSignatureMultiple,
		protocol.ErrSignatureUnsupportedAlg,
		protocol.ErrSignatureInvalidPayload,
		protocol.ErrSignatureInvalid,
		protocol.ErrExpired,
		protocol.ErrIatMissing,
		protocol.ErrIatInFuture,
		protocol.ErrIatToOld,
		protocol.ErrNonceInvalid,
		protocol.ErrAcrInvalid,
		protocol.ErrAuthTimeNotPresent,
		protocol.ErrAuthTimeToOld,
		protocol.ErrAtHash,
	}

	for _, err := range invalidGrantErrors {
		t.Run(err.Error(), func(t *testing.T) {
			got := protocol.DefaultToServerError(err, "test desc")
			b, jsonErr := json.Marshal(got)
			require.NoError(t, jsonErr)

			var m map[string]string
			require.NoError(t, json.Unmarshal(b, &m))
			assert.Equal(t, "invalid_grant", m["error"],
				"expected invalid_grant for %v", err)
			assert.Equal(t, "test desc", m["error_description"])
		})
	}
}

func TestDefaultToServerError_DefaultSentinelErrors(t *testing.T) {
	serverErrors := []struct {
		name string
		err  error
	}{
		{"ErrDiscoveryFailed", protocol.ErrDiscoveryFailed},
		{"ErrSubjectInvalid", protocol.ErrSubjectInvalid},
		{"ErrKeyMultiple", protocol.ErrKeyMultiple},
		{"ErrKeyNone", protocol.ErrKeyNone},
	}

	for _, tt := range serverErrors {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.DefaultToServerError(tt.err, "test desc")
			b, jsonErr := json.Marshal(got)
			require.NoError(t, jsonErr)

			var m map[string]string
			require.NoError(t, json.Unmarshal(b, &m))
			assert.Equal(t, "server_error", m["error"],
				"expected server_error for %v (not in switch)", tt.err)
			assert.Equal(t, "test desc", m["error_description"])
		})
	}
}

func TestError_Is_CrossType(t *testing.T) {
	a := protocol.ErrInvalidRequest()
	b := protocol.ErrInvalidClient()
	assert.False(t, errors.Is(a, b))

	c := protocol.ErrInvalidRequest().WithDescription("foo")
	d := protocol.ErrInvalidRequest().WithDescription("foo")
	assert.True(t, errors.Is(c, d))

	c2 := protocol.ErrInvalidRequest().WithDescription("foo")
	d2 := protocol.ErrInvalidRequest().WithDescription("bar")
	assert.False(t, errors.Is(c2, d2))

	e := protocol.ErrInvalidRequest().WithDescription("x")
	e.State = "s1"
	f := protocol.ErrInvalidRequest().WithDescription("x")
	f.State = "s2"
	assert.False(t, errors.Is(e, f))
}

func mustMarshal(t *testing.T, e *protocol.Error) string {
	t.Helper()
	b, err := json.Marshal(e)
	require.NoError(t, err)
	return string(b)
}

func getDescription(t *testing.T, e *protocol.Error) string {
	t.Helper()
	b, err := json.Marshal(e)
	require.NoError(t, err)
	var m map[string]string
	require.NoError(t, json.Unmarshal(b, &m))
	return m["error_description"]
}
