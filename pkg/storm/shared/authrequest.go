package shared

import (
	"fmt"
	"net"
	"net/url"
	"slices"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// --- Minimal interfaces for authorization request validation ---

// AuthRequestClient is the minimal client interface for auth request validation.
type AuthRequestClient interface {
	GetID() string
	AuthMethod() protocol.AuthMethod
}

// RedirectURIClient is an optional interface for redirect_uri validation.
type RedirectURIClient interface {
	RedirectURIs() []string
}

// RedirectURIGlobClient is an optional interface for glob redirect_uri validation.
type RedirectURIGlobClient interface {
	RedirectURIGlobs() []string
}

// ScopeValidationClient is an optional interface to control scope validation strictness.
type ScopeValidationClient interface {
	StrictScopeValidation() bool
}

// ApplicationTypeClient is an optional interface for application type.
// The return value uses int to allow plugins to define their own constants.
type ApplicationTypeClient interface {
	ApplicationType() int
}

// DevModeClient is an optional interface for dev mode.
type DevModeClient interface {
	DevMode() bool
}

// ResponseTypesProvider is an optional interface for allowed response types.
type ResponseTypesProvider interface {
	ResponseTypes() []protocol.ResponseType
}

// --- Exported validation functions ---

// Application type constants (matching common OIDC implementations).
const (
	ApplicationTypeWeb       = 0 // web
	ApplicationTypeUserAgent = 1 // user_agent
	ApplicationTypeNative    = 2 // native
)

// ValidateAuthRequestParams validates all authorization request parameters.
func ValidateAuthRequestParams(client AuthRequestClient, authReq *protocol.AuthRequest) error {
	if err := ValidateRedirectURI(client, authReq.RedirectURI, authReq.ResponseType); err != nil {
		return err
	}
	return ValidateAuthRequestParamsExceptRedirectURI(client, authReq)
}

// ValidateAuthRequestParamsExceptRedirectURI validates all params except redirect_uri.
// This is called after redirect_uri has been validated separately, so that
// remaining errors can be safely redirected to the registered URI.
func ValidateAuthRequestParamsExceptRedirectURI(client AuthRequestClient, authReq *protocol.AuthRequest) error {
	if err := ValidatePrompt(authReq); err != nil {
		return err
	}
	if err := ValidateScopes(client, authReq); err != nil {
		return err
	}
	if err := ValidatePKCE(authReq); err != nil {
		return err
	}
	if err := ValidateNonce(authReq); err != nil {
		return err
	}
	return ValidateResponseType(client, authReq.ResponseType)
}

// ValidateRedirectURI validates the redirect_uri parameter.
func ValidateRedirectURI(client AuthRequestClient, uri string, responseType protocol.ResponseType) error {
	if uri == "" {
		return protocol.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri is missing")
	}
	unescaped, err := url.QueryUnescape(uri)
	if err != nil {
		return protocol.ErrInvalidRequestRedirectURI().WithDescription("invalid redirect_uri")
	}
	uri = unescaped

	// Check application type and dispatch to appropriate validator.
	appType := ApplicationTypeWeb
	if atc, ok := client.(ApplicationTypeClient); ok {
		appType = atc.ApplicationType()
	}

	if appType == ApplicationTypeNative {
		return validateRedirectURINative(client, uri, responseType)
	}

	// Web / User-Agent clients: HTTPS required with localhost and dev mode exceptions.
	return validateRedirectURIWeb(client, uri, responseType)
}

// ValidatePrompt validates the prompt parameter and mutates authReq accordingly.
// Per OIDC Core §3.1.2.1:
//   - "none" MUST NOT be combined with other values.
//   - "login" forces re-authentication by setting max_age to 0.
func ValidatePrompt(authReq *protocol.AuthRequest) error {
	if len(authReq.Prompt) == 0 {
		return nil
	}

	hasNone := false
	hasOther := false
	for _, prompt := range authReq.Prompt {
		if prompt == protocol.PromptNone {
			hasNone = true
		} else {
			hasOther = true
		}
	}
	if hasNone && hasOther {
		return protocol.ErrInvalidRequest().
			WithDescription("The prompt parameter 'none' must only be used as a single value")
	}

	for _, prompt := range authReq.Prompt {
		switch prompt {
		case protocol.PromptLogin:
			// Force re-authentication.
			zero := uint(0)
			authReq.MaxAge = &zero
		case protocol.PromptConsent:
			// Recognized; enforcement delegated to login UI.
		case protocol.PromptSelectAccount:
			// Recognized; enforcement delegated to login UI.
		case protocol.PromptNone:
			// Valid when used alone; enforcement delegated to login UI.
		default:
			// Unknown prompt values are ignored per robustness principle.
		}
	}
	return nil
}

// ValidateScopes validates the scope parameter.
func ValidateScopes(client AuthRequestClient, authReq *protocol.AuthRequest) error {
	if len(authReq.Scopes) == 0 {
		return protocol.ErrInvalidRequest().WithDescription("scope is missing")
	}

	type scopeProvider interface {
		IsScopeAllowed(string) bool
	}

	// Determine strict mode: client can opt-in via ScopeValidationClient.
	strict := false
	if svc, ok := client.(ScopeValidationClient); ok {
		strict = svc.StrictScopeValidation()
	}

	if strict {
		// Strict mode: reject unsupported scopes with an error.
		for _, scope := range authReq.Scopes {
			if scope == protocol.ScopeOpenID {
				continue
			}
			if sp, ok := client.(scopeProvider); ok {
				if !sp.IsScopeAllowed(scope) {
					return protocol.ErrInvalidScope().WithDescription("scope %s is not allowed for this client", scope)
				}
			} else {
				// No scope provider: any non-openid scope is rejected.
				return protocol.ErrInvalidScope().WithDescription("scope %s is not allowed for this client", scope)
			}
		}
		return nil
	}

	// Lenient mode (default): silently strip unsupported scopes.
	authReq.Scopes = slices.DeleteFunc(authReq.Scopes, func(scope string) bool {
		switch scope {
		case protocol.ScopeOpenID, protocol.ScopeProfile, protocol.ScopeEmail,
			protocol.ScopePhone, protocol.ScopeAddress, protocol.ScopeOfflineAccess:
			return false
		default:
			if sp, ok := client.(scopeProvider); ok {
				return !sp.IsScopeAllowed(scope)
			}
			return true
		}
	})
	return nil
}

// ValidatePKCE checks that code_challenge_method is valid when code_challenge is present.
func ValidatePKCE(authReq *protocol.AuthRequest) error {
	if authReq.CodeChallenge == "" {
		return nil
	}
	switch authReq.CodeChallengeMethod {
	case
		"",
		protocol.CodeChallengeMethodPlain,
		protocol.CodeChallengeMethodS256:
		return nil
	default:
		return protocol.ErrInvalidRequest().
			WithDescription("unsupported code_challenge_method: %s", authReq.CodeChallengeMethod)
	}
}

// ValidateNonce enforces that nonce is present for implicit flows (OIDC Core §3.2.2.1).
func ValidateNonce(authReq *protocol.AuthRequest) error {
	if authReq.ResponseType == protocol.ResponseTypeIDTokenOnly ||
		authReq.ResponseType == protocol.ResponseTypeIDToken {
		if authReq.Nonce == "" {
			return protocol.ErrInvalidRequest().
				WithDescription("nonce is required for implicit flow")
		}
	}
	return nil
}

// ValidateResponseType validates the response_type parameter.
func ValidateResponseType(client AuthRequestClient, responseType protocol.ResponseType) error {
	if responseType == "" {
		return protocol.ErrInvalidRequest().WithDescription("response type is missing")
	}

	if rp, ok := client.(ResponseTypesProvider); ok {
		allowed := rp.ResponseTypes()
		// An empty/nil list means no restriction (all types allowed).
		if len(allowed) > 0 && !slices.Contains(allowed, responseType) {
			return protocol.ErrUnauthorizedClient().WithDescription("requested response type not allowed")
		}
	}
	return nil
}

// --- Internal helpers ---

// IsLocalhost returns true if the hostname is a loopback address.
// Per RFC 8252 §7.3, only 127.0.0.1 and ::1 are loopback addresses.
func IsLocalhost(host string) bool {
	return host == "localhost" ||
		host == "127.0.0.1" ||
		host == "::1"
}

// HTTPLoopbackOrLocalhost parses a URL and returns true if it uses HTTP/HTTPS
// and points to a loopback address.
func HTTPLoopbackOrLocalhost(rawURL string) (*url.URL, bool) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
		hostName := parsedURL.Hostname()
		return parsedURL, hostName == "localhost" || net.ParseIP(hostName).IsLoopback()
	}
	return nil, false
}

// ValidateRemoteURL validates a user-provided URL to prevent SSRF attacks.
// Rules:
//   - Scheme must be https (or http for localhost only)
//   - For non-localhost URLs, DNS is resolved and private/link-local/loopback IPs are blocked
func ValidateRemoteURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Host == "" {
		return fmt.Errorf("missing host")
	}

	host := parsed.Hostname()
	local := IsLocalhost(host)

	switch parsed.Scheme {
	case "https":
		// OK
	case "http":
		if !local {
			return fmt.Errorf("http scheme only allowed for localhost")
		}
	default:
		return fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}

	if !local {
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("DNS lookup failed: %w", err)
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
				ip.IsPrivate() || ip.IsUnspecified() {
				return fmt.Errorf("host resolves to private IP: %s", ip)
			}
		}
	}

	return nil
}

// equalURI returns true if two URLs have the same path and raw query.
func equalURI(url1, url2 *url.URL) bool {
	if url1 == nil || url2 == nil {
		return false
	}
	return url1.Path == url2.Path && url1.RawQuery == url2.RawQuery
}

func validateRedirectURIWeb(client AuthRequestClient, uri string, responseType protocol.ResponseType) error {
	u, err := url.Parse(uri)
	if err != nil {
		return protocol.ErrInvalidRequestRedirectURI().WithDescription("invalid redirect_uri")
	}

	// Custom schemes are not allowed for web clients.
	if u.Scheme != "http" && u.Scheme != "https" {
		return protocol.ErrInvalidRequestRedirectURI().WithDescription("custom scheme not allowed for web clients")
	}

	// HTTPS is always allowed.
	if u.Scheme == "https" {
		return checkRedirectURIAgainstClient(client, uri)
	}

	// HTTP is allowed for localhost.
	if u.Scheme == "http" && IsLocalhost(u.Hostname()) {
		return checkRedirectURIAgainstClient(client, uri)
	}

	// DevMode allows HTTP.
	if dc, ok := client.(DevModeClient); ok && dc.DevMode() {
		return checkRedirectURIAgainstClient(client, uri)
	}

	// Confidential clients in code flow may use HTTP (legacy compatibility).
	if u.Scheme == "http" && responseType == protocol.ResponseTypeCode {
		if amc, ok := client.(interface{ AuthMethod() protocol.AuthMethod }); ok {
			if amc.AuthMethod() == protocol.AuthMethodBasic || amc.AuthMethod() == protocol.AuthMethodPrivateKeyJWT {
				return checkRedirectURIAgainstClient(client, uri)
			}
		}
	}

	return protocol.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri must use https")
}

func validateRedirectURINative(client AuthRequestClient, uri string, responseType protocol.ResponseType) error {
	u, err := url.Parse(uri)
	if err != nil {
		return protocol.ErrInvalidRequestRedirectURI().WithDescription("invalid redirect_uri")
	}

	parsedURL, isLoopback := HTTPLoopbackOrLocalhost(uri)
	isCustomScheme := u.Scheme != "http" && u.Scheme != "https"

	// Check against registered redirect URIs first.
	if err := checkRedirectURIAgainstClient(client, uri); err == nil {
		// Registered URI matched.
		if dc, ok := client.(DevModeClient); ok && dc.DevMode() {
			return nil
		}
		if !isLoopback && u.Scheme == "https" {
			return nil
		}
		if isLoopback || isCustomScheme {
			return nil
		}
		return protocol.ErrInvalidRequestRedirectURI().WithDescription("http redirect_uri not allowed for native clients")
	}

	// Not in registered URIs: only loopback addresses get a second chance.
	if !isLoopback {
		return protocol.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri not registered")
	}

	// For loopback, check if any registered URI has the same path/query.
	if rc, ok := client.(RedirectURIClient); ok {
		for _, registered := range rc.RedirectURIs() {
			redirectURI, ok := HTTPLoopbackOrLocalhost(registered)
			if ok && equalURI(parsedURL, redirectURI) {
				return nil
			}
		}
	}

	return protocol.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri not registered")
}

// checkRedirectURIAgainstClient checks the URI against registered redirect URIs
// and optional glob patterns.
func checkRedirectURIAgainstClient(client AuthRequestClient, uri string) error {
	// Direct match against registered URIs.
	if rc, ok := client.(RedirectURIClient); ok {
		if slices.Contains(rc.RedirectURIs(), uri) {
			return nil
		}
	}

	// Glob match (only if direct match failed).
	if gc, ok := client.(RedirectURIGlobClient); ok {
		for _, pattern := range gc.RedirectURIGlobs() {
			matched, err := doublestar.Match(pattern, uri)
			if err != nil {
				return protocol.ErrServerError().WithParent(err)
			}
			if matched {
				return nil
			}
		}
	}

	return protocol.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri not registered")
}
