// This file contains the OAuth 2.1 / OpenID Connect error types and the
// DefaultToServerError mapping function. All error codes are defined per
// the relevant RFC specifications.

package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
)

// ---------------------------------------------------------------------------
// Sentinel errors for internal token validation failures.
// These are mapped to OAuth error codes by DefaultToServerError.
// ---------------------------------------------------------------------------

var (
	// ErrParse indicates that parsing of the JWT or request failed.
	ErrParse = errors.New("parsing of request failed")

	// ErrIssuerInvalid indicates the token issuer does not match.
	ErrIssuerInvalid = errors.New("issuer does not match")

	// ErrDiscoveryFailed indicates OpenID Provider Configuration Discovery has failed.
	ErrDiscoveryFailed = errors.New("OpenID Provider Configuration Discovery has failed")

	// ErrSubjectMissing indicates the subject claim is missing from the token.
	ErrSubjectMissing = errors.New("subject missing")

	// ErrSubjectInvalid indicates delegation is not allowed:
	// issuer and sub must be identical for non-delegated tokens.
	ErrSubjectInvalid = errors.New("delegation not allowed, issuer and sub must be identical")

	// ErrAudience indicates the audience claim is not valid.
	ErrAudience = errors.New("audience is not valid")

	// ErrAzpMissing indicates azp (authorized party) is not set when the token
	// is valid for multiple audiences.
	ErrAzpMissing = errors.New("authorized party is not set. If Token is valid for multiple audiences, azp must not be empty")

	// ErrAzpInvalid indicates the authorized party is not valid.
	ErrAzpInvalid = errors.New("authorized party is not valid")

	// ErrSignatureMissing indicates the id_token does not contain a signature.
	ErrSignatureMissing = errors.New("id_token does not contain a signature")

	// ErrSignatureMultiple indicates the id_token contains multiple signatures.
	ErrSignatureMultiple = errors.New("id_token contains multiple signatures")

	// ErrSignatureUnsupportedAlg indicates the signature algorithm is not supported.
	ErrSignatureUnsupportedAlg = errors.New("signature algorithm not supported")

	// ErrSignatureInvalidPayload indicates the signature does not match the payload.
	ErrSignatureInvalidPayload = errors.New("signature does not match Payload")

	// ErrSignatureInvalid indicates an invalid signature.
	ErrSignatureInvalid = errors.New("invalid signature")

	// ErrExpired indicates the token has expired (exp claim).
	ErrExpired = errors.New("token has expired")

	// ErrIatMissing indicates the iat (issued-at) claim is missing.
	ErrIatMissing = errors.New("issuedAt of token is missing")

	// ErrIatInFuture indicates the iat claim is in the future.
	ErrIatInFuture = errors.New("issuedAt of token is in the future")

	// ErrIatToOld indicates the iat claim exceeds the maximum age.
	ErrIatToOld = errors.New("issuedAt of token is to old")

	// ErrNbfInFuture indicates the nbf claim is in the future.
	ErrNbfInFuture = errors.New("notBefore of token is in the future")

	// ErrNonceInvalid indicates the nonce claim does not match the expected value.
	ErrNonceInvalid = errors.New("nonce does not match")

	// ErrAcrInvalid indicates the acr (Authentication Context Class Reference)
	// claim does not satisfy the requested level.
	ErrAcrInvalid = errors.New("acr is invalid")

	// ErrAuthTimeNotPresent indicates the auth_time claim is missing from the token.
	ErrAuthTimeNotPresent = errors.New("claim `auth_time` of token is missing")

	// ErrAuthTimeToOld indicates the auth_time claim exceeds the maximum age.
	ErrAuthTimeToOld = errors.New("auth time of token is too old")

	// ErrAtHash indicates the at_hash claim does not correspond to the access token.
	ErrAtHash = errors.New("at_hash does not correspond to access token")

	// ErrKeyMultiple indicates multiple possible keys match for JWT verification.
	ErrKeyMultiple = errors.New("multiple possible keys match")

	// ErrKeyNone indicates no matching key was found for JWT verification.
	ErrKeyNone = errors.New("no possible keys matches")
)

// ---------------------------------------------------------------------------
// errorType — OAuth 2.1 / OIDC protocol-level error codes.
// ---------------------------------------------------------------------------

type errorType string

const (
	// ---- OAuth 2.0 Token Endpoint Error Response (RFC 6749 §5.2) ----

	// InvalidRequest: The request is missing a required parameter, includes an
	// unsupported parameter value (other than grant type), repeats a parameter,
	// includes multiple credentials, uses more than one mechanism for
	// authenticating the client, or is otherwise malformed.
	// RFC 6749 §5.2 (OAuth 2.0)
	InvalidRequest errorType = "invalid_request"

	// InvalidClient: Client authentication failed (e.g., unknown client, no
	// client authentication included, or unsupported authentication method).
	// RFC 6749 §5.2 (OAuth 2.0)
	InvalidClient errorType = "invalid_client"

	// InvalidGrant: The provided authorization grant (e.g., authorization code,
	// resource owner credentials) or refresh token is invalid, expired, revoked,
	// does not match the redirection URI used in the authorization request, or
	// was issued to another client.
	// RFC 6749 §5.2 (OAuth 2.0)
	InvalidGrant errorType = "invalid_grant"

	// UnauthorizedClient: The authenticated client is not authorized to use this
	// authorization grant type.
	// RFC 6749 §5.2 (OAuth 2.0)
	UnauthorizedClient errorType = "unauthorized_client"

	// UnsupportedGrantType: The authorization grant type is not supported by the
	// authorization server.
	// RFC 6749 §5.2 (OAuth 2.0)
	UnsupportedGrantType errorType = "unsupported_grant_type"

	// InvalidScope: The requested scope is invalid, unknown, malformed, or
	// exceeds the scope granted by the resource owner.
	// RFC 6749 §5.2 (OAuth 2.0)
	InvalidScope errorType = "invalid_scope"

	// ServerError: The authorization server encountered an unexpected condition
	// that prevented it from fulfilling the request.
	// RFC 6749 §5.2 (OAuth 2.0)
	ServerError errorType = "server_error"

	// TemporarilyUnavailable: The authorization server is currently unable to
	// handle the request due to a temporary overloading or maintenance of the
	// server. (This error code has no constructor — use the constant directly
	// when building an Error manually.)
	// RFC 6749 §5.2 (OAuth 2.0)
	TemporarilyUnavailable errorType = "temporarily_unavailable"

	// ---- OAuth 2.0 Authorization Endpoint Error (RFC 6749 §4.1.2.1) ----

	// AccessDenied: The resource owner or authorization server denied the
	// request.
	// RFC 6749 §4.1.2.1 (OAuth 2.0) / RFC 8628 §3.5 (Device Auth)
	AccessDenied errorType = "access_denied"

	// UnsupportedResponseType: The authorization server does not support
	// obtaining an authorization code using this method.
	// RFC 6749 §4.1.2.1 (OAuth 2.0)
	UnsupportedResponseType errorType = "unsupported_response_type"

	// ---- OIDC Core 1.0 Authentication Error Response (§3.1.2.6) ----

	// InteractionRequired: The Authorization Server requires End-User
	// interaction of some form to proceed.
	// OIDC Core 1.0 §3.1.2.6
	InteractionRequired errorType = "interaction_required"

	// LoginRequired: The Authorization Server requires End-User authentication.
	// OIDC Core 1.0 §3.1.2.6
	LoginRequired errorType = "login_required"

	// AccountSelectionRequired: The End-User is required to select a session at
	// the Authorization Server.
	// OIDC Core 1.0 §3.1.2.6
	AccountSelectionRequired errorType = "account_selection_required"

	// ConsentRequired: The Authorization Server requires End-User consent.
	// OIDC Core 1.0 §3.1.2.6
	ConsentRequired errorType = "consent_required"

	// RegistrationNotSupported: The OP does not support use of the
	// registration parameter.
	// OIDC Core 1.0 §3.1.2.6
	RegistrationNotSupported errorType = "registration_not_supported"

	// ---- OIDC Core 1.0 Request Object (§6.1) ----

	// RequestNotSupported: The OP does not support use of the request parameter
	// defined in Section 6.
	// OIDC Core 1.0 §6.1
	RequestNotSupported errorType = "request_not_supported"

	// ---- OIDC Core 1.0 Request URI (§6.3) ----

	// RequestURINotSupported: The OP does not support use of the request_uri
	// parameter defined in Section 6.3.
	// OIDC Core 1.0 §6.3
	RequestURINotSupported errorType = "request_uri_not_supported"

	// ---- RFC 9101 JAR / OIDC Core §6 ----

	// InvalidRequestObject: The request object is invalid, malformed,
	// has an invalid signature, or fails validation.
	// RFC 9101 §6.3 / OIDC Core §6.1
	InvalidRequestObject errorType = "invalid_request_object"

	// ---- RFC 8628 Device Authorization Grant (§3.5) ----

	// AuthorizationPending: The authorization request is still pending as the
	// end user hasn't yet completed the user-interaction steps.
	// RFC 8628 §3.5 (OAuth 2.0 Device Authorization Grant)
	AuthorizationPending errorType = "authorization_pending"

	// SlowDown: A variant of authorization_pending. The authorization request
	// is still pending and polling should continue, but the interval MUST be
	// increased by 5 seconds for this and all subsequent requests.
	// RFC 8628 §3.5 (OAuth 2.0 Device Authorization Grant)
	SlowDown errorType = "slow_down"

	// ExpiredToken: The device_code has expired and the device authorization
	// session has concluded.
	// RFC 8628 §3.5 (OAuth 2.0 Device Authorization Grant)
	ExpiredToken errorType = "expired_token"

	// ---- RFC 8693 OAuth 2.0 Token Exchange (§2.2.2) ----

	// InvalidTarget: The requested target resource is invalid, unknown, or
	// the audience parameter for the token being exchanged is not accepted.
	// RFC 8693 §2.2.2 (OAuth 2.0 Token Exchange)
	InvalidTarget errorType = "invalid_target"

	// ---- RFC 7591 OAuth 2.0 Dynamic Client Registration (§3.2.2) ----

	// InvalidClientMetadata: The value of one of the client metadata fields
	// is invalid or the server rejects this metadata for other reasons.
	// RFC 7591 §3.2.2
	InvalidClientMetadata errorType = "invalid_client_metadata"
)

// ---------------------------------------------------------------------------
// Error constructor functions.
// Each returns a func() *Error that creates a fresh instance, allowing
// callers to chain .WithDescription() and .WithParent() without affecting
// the shared template.
// ---------------------------------------------------------------------------

var (
	// ---- OAuth 2.0 Token Endpoint (RFC 6749 §5.2) ----

	ErrInvalidRequest = func() *Error {
		return &Error{ErrorType: InvalidRequest}
	}
	ErrInvalidRequestRedirectURI = func() *Error {
		return &Error{ErrorType: InvalidRequest, redirectDisabled: true}
	}
	ErrInvalidClient = func() *Error {
		return &Error{ErrorType: InvalidClient}
	}
	ErrInvalidGrant = func() *Error {
		return &Error{ErrorType: InvalidGrant}
	}
	ErrUnauthorizedClient = func() *Error {
		return &Error{ErrorType: UnauthorizedClient}
	}
	ErrUnsupportedGrantType = func() *Error {
		return &Error{ErrorType: UnsupportedGrantType}
	}
	ErrInvalidScope = func() *Error {
		return &Error{ErrorType: InvalidScope}
	}
	ErrServerError = func() *Error {
		return &Error{ErrorType: ServerError}
	}

	// ---- OAuth 2.0 Authorization Endpoint (RFC 6749 §4.1.2.1) ----

	ErrAccessDenied = func() *Error {
		return &Error{
			ErrorType:   AccessDenied,
			Description: "The authorization request was denied.",
		}
	}
	ErrUnsupportedResponseType = func() *Error {
		return &Error{ErrorType: UnsupportedResponseType}
	}

	// ---- OIDC Core 1.0 Authentication Error (§3.1.2.6) ----

	ErrInteractionRequired = func() *Error {
		return &Error{ErrorType: InteractionRequired}
	}
	ErrLoginRequired = func() *Error {
		return &Error{ErrorType: LoginRequired}
	}
	ErrAccountSelectionRequired = func() *Error {
		return &Error{ErrorType: AccountSelectionRequired}
	}
	ErrConsentRequired = func() *Error {
		return &Error{ErrorType: ConsentRequired}
	}
	ErrRegistrationNotSupported = func() *Error {
		return &Error{ErrorType: RegistrationNotSupported}
	}

	// ---- OIDC Core 1.0 Request Object (§6.1) ----

	ErrRequestNotSupported = func() *Error {
		return &Error{ErrorType: RequestNotSupported}
	}

	// ---- OIDC Core 1.0 Request URI (§6.3) ----

	ErrRequestURINotSupported = func() *Error {
		return &Error{ErrorType: RequestURINotSupported}
	}

	// ---- RFC 9101 JAR / OIDC Core §6 ----

	ErrInvalidRequestObject = func() *Error {
		return &Error{ErrorType: InvalidRequestObject}
	}

	// ---- RFC 8628 Device Authorization Grant (§3.5) ----

	ErrAuthorizationPending = func() *Error {
		return &Error{
			ErrorType:   AuthorizationPending,
			Description: "The client SHOULD repeat the access token request to the token endpoint, after interval from device authorization response.",
		}
	}
	ErrSlowDown = func() *Error {
		return &Error{
			ErrorType:   SlowDown,
			Description: "Polling should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests.",
		}
	}
	ErrExpiredDeviceCode = func() *Error {
		return &Error{
			ErrorType:   ExpiredToken,
			Description: "The \"device_code\" has expired.",
		}
	}

	// ---- RFC 8693 Token Exchange (§2.2.2) ----

	ErrInvalidTarget = func() *Error {
		return &Error{
			ErrorType:   InvalidTarget,
			Description: "The requested audience or target is invalid.",
		}
	}

	// ---- RFC 7591 Dynamic Client Registration (§3.2.2) ----

	ErrInvalidClientMetadata = func() *Error {
		return &Error{ErrorType: InvalidClientMetadata}
	}
)

// ---------------------------------------------------------------------------
// Error — OAuth 2.1 / OIDC protocol error.
//
// Implements the error interface and provides chainable builder methods for
// attaching description text, parent errors, and metadata.
//
// JSON serialization follows:
//
//	{
//	  "error": "...",
//	  "error_description": "...",
//	  "state": "...",
//	  "session_state": "..."
//	}
//
// Reference: RFC 6749 §5.2 (OAuth 2.0 Error Response)
// ---------------------------------------------------------------------------

type Error struct {
	Parent           error     `json:"-" schema:"-"`
	ErrorType        errorType `json:"error" schema:"error"`
	Description      string    `json:"error_description,omitempty" schema:"error_description,omitempty"`
	State            string    `json:"state,omitempty" schema:"state,omitempty"`
	SessionState     string    `json:"session_state,omitempty" schema:"session_state,omitempty"`
	redirectDisabled bool      `schema:"-"`
	returnParent     bool      `schema:"-"`
}

// MarshalJSON serialises the error per RFC 6749 §5.2 JSON format.
func (e *Error) MarshalJSON() ([]byte, error) {
	m := struct {
		Error            errorType `json:"error"`
		ErrorDescription string    `json:"error_description,omitempty"`
		State            string    `json:"state,omitempty"`
		SessionState     string    `json:"session_state,omitempty"`
		Parent           string    `json:"parent,omitempty"`
	}{
		Error:            e.ErrorType,
		ErrorDescription: e.Description,
		State:            e.State,
		SessionState:     e.SessionState,
	}
	if e.returnParent && e.Parent != nil {
		m.Parent = e.Parent.Error()
	}
	return json.Marshal(m)
}

// Error implements the error interface.
func (e *Error) Error() string {
	message := "ErrorType=" + string(e.ErrorType)
	if e.Description != "" {
		message += " Description=" + e.Description
	}
	if e.Parent != nil {
		message += " Parent=" + e.Parent.Error()
	}
	return message
}

// Unwrap enables errors.Is / errors.As traversal.
func (e *Error) Unwrap() error {
	return e.Parent
}

// Is implements errors.Is comparison based on ErrorType and optional metadata.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.ErrorType == t.ErrorType &&
		(e.Description == t.Description || t.Description == "") &&
		(e.State == t.State || t.State == "") &&
		(e.SessionState == t.SessionState || t.SessionState == "")
}

// WithParent chains a parent error for diagnostics.
func (e *Error) WithParent(err error) *Error {
	e.Parent = err
	return e
}

// WithReturnParentToClient controls whether the parent error message is
// included in the JSON response body. Use with caution — parent errors may
// expose sensitive implementation details.
func (e *Error) WithReturnParentToClient(b bool) *Error {
	e.returnParent = b
	return e
}

// WithDescription sets a human-readable description.
func (e *Error) WithDescription(desc string, args ...any) *Error {
	e.Description = fmt.Sprintf(desc, args...)
	return e
}

// IsRedirectDisabled reports whether this error should be rendered as a
// direct JSON response rather than a redirect (e.g. when redirect_uri is
// missing or invalid).
func (e *Error) IsRedirectDisabled() bool {
	return e.redirectDisabled
}

// ---------------------------------------------------------------------------
// DefaultToServerError — maps internal sentinel errors to OAuth error codes.
//
// Mapping rules:
//   - ErrParse                                              → ErrInvalidRequest
//   - ErrIssuerInvalid / ErrExpired / ErrSignatureXXX / …   → ErrInvalidGrant
//   - ErrDiscoveryFailed / unknown                          → ErrServerError
//   - If the error is already an *Error                     → cloned as-is
// ---------------------------------------------------------------------------

func DefaultToServerError(err error, description string) *Error {
	protoErr := new(Error)
	if ok := errors.As(err, &protoErr); ok {
		clone := *protoErr
		return &clone
	}
	switch {
	case errors.Is(err, ErrParse):
		return ErrInvalidRequest().WithParent(err).WithDescription("%s", description)
	case errors.Is(err, ErrIssuerInvalid),
		errors.Is(err, ErrSubjectMissing),
		errors.Is(err, ErrAudience),
		errors.Is(err, ErrAzpMissing),
		errors.Is(err, ErrAzpInvalid),
		errors.Is(err, ErrSignatureMissing),
		errors.Is(err, ErrSignatureMultiple),
		errors.Is(err, ErrSignatureUnsupportedAlg),
		errors.Is(err, ErrSignatureInvalidPayload),
		errors.Is(err, ErrSignatureInvalid),
		errors.Is(err, ErrExpired),
		errors.Is(err, ErrIatMissing),
		errors.Is(err, ErrIatInFuture),
		errors.Is(err, ErrIatToOld),
		errors.Is(err, ErrNbfInFuture),
		errors.Is(err, ErrNonceInvalid),
		errors.Is(err, ErrAcrInvalid),
		errors.Is(err, ErrAuthTimeNotPresent),
		errors.Is(err, ErrAuthTimeToOld),
		errors.Is(err, ErrAtHash):
		return ErrInvalidGrant().WithParent(err).WithDescription("%s", description)
	default:
		return ErrServerError().WithParent(err).WithDescription("%s", description)
	}
}

// LogLevel returns the appropriate slog level for this error.
// ServerError maps to LevelError, AuthorizationPending to LevelInfo,
// everything else to LevelWarn.
func (e *Error) LogLevel() slog.Level {
	if e.ErrorType == ServerError {
		return slog.LevelError
	}
	if e.ErrorType == AuthorizationPending {
		return slog.LevelInfo
	}
	return slog.LevelWarn
}

// LogValue implements slog.LogValuer for structured logging.
func (e *Error) LogValue() slog.Value {
	attrs := make([]slog.Attr, 0, 6)
	if e.Parent != nil {
		attrs = append(attrs, slog.Any("parent", e.Parent))
	}
	if e.Description != "" {
		attrs = append(attrs, slog.String("description", e.Description))
	}
	if e.ErrorType != "" {
		attrs = append(attrs, slog.String("type", string(e.ErrorType)))
	}
	if e.State != "" {
		attrs = append(attrs, slog.String("state", e.State))
	}
	if e.SessionState != "" {
		attrs = append(attrs, slog.String("session_state", e.SessionState))
	}
	if e.redirectDisabled {
		attrs = append(attrs, slog.Bool("redirect_disabled", e.redirectDisabled))
	}
	return slog.GroupValue(attrs...)
}

// ToOAuthError maps an OAuth error code string (e.g. "access_denied")
// to a protocol.Error. Returns ErrInvalidRequest for unknown codes.
func ToOAuthError(code string) *Error {
	switch errorType(code) {
	case AccessDenied:
		return ErrAccessDenied()
	case InvalidClient:
		return ErrInvalidClient()
	case InvalidGrant:
		return ErrInvalidGrant()
	case InvalidScope:
		return ErrInvalidScope()
	case UnauthorizedClient:
		return ErrUnauthorizedClient()
	case UnsupportedResponseType:
		return ErrUnsupportedResponseType()
	case InteractionRequired:
		return ErrInteractionRequired()
	case LoginRequired:
		return ErrLoginRequired()
	case ServerError:
		return ErrServerError()
	default:
		return ErrInvalidRequest()
	}
}
