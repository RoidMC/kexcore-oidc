package authorization

import (
	"context"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// --- optional client interfaces ---

// SessionStateClient is optionally implemented by clients that support
// OpenID Connect Session Management. When implemented, session_state
// is included in authorization responses.
type SessionStateClient interface {
	storm.Client
	GetSessionState() string
}

// RedirectURIClient is optionally implemented by clients that need
// redirect URI validation beyond the basic check.
type RedirectURIClient interface {
	storm.Client
	RedirectURIs() []string
}

// RedirectURIGlobClient is optionally implemented by clients that need
// glob/wildcard redirect URI matching.
type RedirectURIGlobClient interface {
	storm.Client
	RedirectURIGlobs() []string
}

// ApplicationTypeClient is optionally implemented by clients that declare
// their application type (web, user_agent, native).
type ApplicationTypeClient interface {
	storm.Client
	ApplicationType() ApplicationType
}

// ApplicationType defines the type of OAuth 2.0 / OIDC client.
type ApplicationType = int

// Application type constants (re-exported from shared package).
const (
	ApplicationTypeWeb       = shared.ApplicationTypeWeb       // web
	ApplicationTypeUserAgent = shared.ApplicationTypeUserAgent // user_agent
	ApplicationTypeNative    = shared.ApplicationTypeNative    // native
)

// DevModeClient is optionally implemented by clients that enable
// development mode, which relaxes certain security checks.
type DevModeClient interface {
	storm.Client
	DevMode() bool
}

// --- response types ---

// codeResponse is the authorization code response payload.
type codeResponse struct {
	Code         string `schema:"code"`
	State        string `schema:"state,omitempty"`
	SessionState string `schema:"session_state,omitempty"`
}

// --- validator extension ---

// AuthorizeValidator is an optional interface that can be implemented
// by the plugin's storage (or another component) to provide custom
// authorization request validation.
//
// When implemented, ValidateAuthRequest is called after default
// validation in handleAuthorize, allowing additional checks.
type AuthorizeValidator interface {
	// ValidateAuthRequest performs custom validation of the authorization
	// request. It receives the resolved client and parsed request, and
	// should return an error if validation fails.
	ValidateAuthRequest(client storm.Client, authReq *protocol.AuthRequest) error
}

// AuthorizeValidatorClient is optionally implemented by clients that
// provide a custom AuthorizeValidator for per-client validation logic.
type AuthorizeValidatorClient interface {
	storm.Client
	AuthorizeValidator() AuthorizeValidator
}

// IDTokenClaimsExtender is optionally implemented by AuthRequest to provide
// additional claims for the ID token (e.g. acr, amr, c_hash).
//
// When implemented, the returned claims are merged into the ID token's
// payload. Standard claims (iss, sub, aud, iat, exp, nonce, at_hash)
// set by the plugin take precedence and cannot be overridden.
type IDTokenClaimsExtender interface {
	ExtraIDTokenClaims() map[string]any
}

// IDTokenLifetimeProvider is optionally implemented by Client to control
// the lifetime of issued ID tokens.
//
// When not implemented, the default lifetime (1 hour) is used.
type IDTokenLifetimeProvider interface {
	IDTokenLifetime() time.Duration
}

// JARMSigner is optionally implemented by a plugin to provide JARM
// (JWT Secured Authorization Response Mode) support per RFC 9101.
//
// When implemented, the authorization response is signed as a JWT
// and returned using the requested JARM response mode (query.jwt,
// fragment.jwt, or form_post.jwt).
type JARMSigner interface {
	// SignAuthResponse signs the authorization response parameters
	// as a JWT. The ctx is used to derive the issuer URL. The params
	// map contains the response fields (code, state, etc.). The
	// clientID is used for audience validation.
	// Returns the compact JWT string.
	SignAuthResponse(ctx context.Context, params map[string]string, clientID string) (string, error)
}
