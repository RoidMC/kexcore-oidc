package authorization

import (
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
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
// glob/wildcard redirect URI matching. See [doublestar.Match] for glob
// interpretation.
//
// Note: globbing is not permitted by the OIDC standard and can have
// security implications. It is advised to only use this in rare cases
// such as development mode.
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
type ApplicationType int

const (
	ApplicationTypeWeb       ApplicationType = iota // web
	ApplicationTypeUserAgent                        // user_agent
	ApplicationTypeNative                           // native
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
