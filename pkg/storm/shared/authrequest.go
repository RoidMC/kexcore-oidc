package shared

import (
	"crypto/x509"
	"fmt"
	"log/slog"
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

// FAPIProfileClient is an optional interface for FAPI 2.0 profile detection.
type FAPIProfileClient interface {
	FAPIProfile() bool
}

// RequestObjectSigningAlgProvider is an optional interface for clients that
// require signed request objects (e.g. FAPI 2.0 signed_non_repudiation).
// When implemented and returning a non-empty string, the authorization server
// MUST reject authorization/PAR requests without a signed request object.
type RequestObjectSigningAlgProvider interface {
	RequestObjectSigningAlg() string
}

// ValidateSignedRequestObjectRequired returns an error if the client is
// configured to require signed request objects but the request does not
// contain one. It is used by both the PAR and authorization endpoints.
//
// A signed request object is required when the client has
// request_object_signing_alg configured.
//
// Note: FAPI 2.0 Security Profile does NOT mandate signed request objects.
// Only FAPI 2.0 Message Signing (a separate profile) does, and that is
// enforced via the client's request_object_signing_alg setting.
func ValidateSignedRequestObjectRequired(client interface{}, hasRequestObject bool) error {
	algProvider, ok := client.(RequestObjectSigningAlgProvider)
	if !ok || algProvider.RequestObjectSigningAlg() == "" {
		return nil
	}
	if !hasRequestObject {
		return protocol.ErrInvalidRequest().WithDescription("signed request object is required for this client")
	}
	return nil
}

// SenderConstrainingProvider is an optional interface for clients that
// require sender-constrained tokens (FAPI 2.0 Security Profile).
// When RequireDPoP returns true, the token endpoint MUST require a DPoP proof.
// When RequireMtls returns true, the token endpoint MUST require mTLS client auth.
type SenderConstrainingProvider interface {
	RequireDPoP() bool
	RequireMtls() bool
}

// ClientCertBoundAuthenticator is an optional interface for clients that
// require the TLS client certificate to match a specific identity (e.g.,
// certificate CN must match client_id). When ValidateClientCert returns
// a non-nil error, the token/bc-authorize endpoint rejects the request.
//
// This is disabled by default (clients not implementing this interface
// skip certificate identity validation). Implement this on your Client
// struct to enable per-client mTLS identity verification per RFC 8705 §2.1.
//
// SECURITY: If you have multiple tls_client_auth clients sharing the same
// TLS certificate infrastructure, you MUST implement this interface to prevent
// cross-client access. Without it, any client holding a valid TLS certificate
// can impersonate another tls_client_auth client by providing a different
// client_id in the request.
type ClientCertBoundAuthenticator interface {
	ValidateClientCert(cert *x509.Certificate, clientID string) error
}

// IDTokenSignedResponseAlgProvider is an optional interface for clients that
// specify a preferred ID token signing algorithm (id_token_signed_response_alg).
// When implemented and returning a non-empty string, the token endpoint uses
// this algorithm to sign the ID token instead of the default.
type IDTokenSignedResponseAlgProvider interface {
	IDTokenSignedResponseAlg() string
}

// UserInfoSignedResponseAlgProvider is an optional interface for clients that
// specify a preferred UserInfo signing algorithm (userinfo_signed_response_alg).
// When implemented and returning a non-empty string, the userinfo endpoint uses
// this algorithm to sign the JWT response instead of the default.
type UserInfoSignedResponseAlgProvider interface {
	UserInfoSignedResponseAlg() string
}

// --- Exported validation functions ---

// Application type constants (matching common OIDC implementations).
const (
	ApplicationTypeWeb       = 0 // web
	ApplicationTypeUserAgent = 1 // user_agent
	ApplicationTypeNative    = 2 // native
)

// ValidateAuthRequestParams validates all authorization request parameters.
// defaultScopes are applied when the client omits the scope parameter (optional).
func ValidateAuthRequestParams(client AuthRequestClient, authReq *protocol.AuthRequest, defaultScopes ...string) error {
	if err := ValidateRedirectURI(client, authReq.RedirectURI, authReq.ResponseType); err != nil {
		return err
	}
	return ValidateAuthRequestParamsExceptRedirectURI(client, authReq, defaultScopes...)
}

// ValidateAuthRequestParamsExceptRedirectURI validates all params except redirect_uri.
// This is called after redirect_uri has been validated separately, so that
// remaining errors can be safely redirected to the registered URI.
// defaultScopes are applied when the client omits the scope parameter (optional).
func ValidateAuthRequestParamsExceptRedirectURI(client AuthRequestClient, authReq *protocol.AuthRequest, defaultScopes ...string) error {
	if err := ValidatePrompt(authReq); err != nil {
		return err
	}
	if err := ValidateScopes(client, authReq, defaultScopes...); err != nil {
		return err
	}
	// FAPI 2.0 Security Profile §5.2.2-18: PKCE is required for FAPI clients.
	if fc, ok := client.(FAPIProfileClient); ok && fc.FAPIProfile() && authReq.CodeChallenge == "" {
		return protocol.ErrInvalidRequest().WithDescription("PKCE is required for FAPI clients")
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
// If the client omits the scope parameter, defaultScopes are applied when provided.
// Per RFC 6749 §4.1.1: "If the client omits the scope parameter when requesting
// authorization, the authorization server MUST either process the request using
// a pre-defined default value or fail the request indicating an invalid scope."
func ValidateScopes(client AuthRequestClient, authReq *protocol.AuthRequest, defaultScopes ...string) error {
	// DEBUG: trace scope validation input
	slog.Info("ValidateScopes: input",
		slog.Any("scopes", authReq.Scopes),
		slog.Int("scopes_len", len(authReq.Scopes)),
		slog.Any("default_scopes", defaultScopes),
	)

	if len(authReq.Scopes) == 0 {
		if len(defaultScopes) > 0 {
			authReq.Scopes = defaultScopes
			slog.Info("ValidateScopes: applied default scopes", slog.Any("scopes", authReq.Scopes))
			return nil
		}
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
	beforeLen := len(authReq.Scopes)
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
	slog.Info("ValidateScopes: after lenient filtering",
		slog.Any("scopes_before_len", beforeLen),
		slog.Any("scopes_after", authReq.Scopes),
		slog.Int("scopes_after_len", len(authReq.Scopes)),
	)
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

// ValidateNonce enforces that nonce is present for implicit and hybrid flows
// (OIDC Core §3.2.2.1, §3.3.2.1).
func ValidateNonce(authReq *protocol.AuthRequest) error {
	switch authReq.ResponseType {
	case protocol.ResponseTypeIDTokenOnly,
		protocol.ResponseTypeIDToken,
		protocol.ResponseTypeCodeIDToken,
		protocol.ResponseTypeCodeIDTokenToken:
		if authReq.Nonce == "" {
			return protocol.ErrInvalidRequest().
				WithDescription("nonce is required for implicit/hybrid flow")
		}
	}
	return nil
}

// ValidateResponseType validates the response_type parameter.
func ValidateResponseType(client AuthRequestClient, responseType protocol.ResponseType) error {
	if responseType == "" {
		return protocol.ErrInvalidRequest().WithDescription("response type is missing")
	}

	// FAPI 2.0 Security Profile §5.3.2.2: only response_type=code is permitted.
	// Hybrid and implicit flows are not allowed because they return tokens via
	// the browser front-channel where they may be leaked.
	if fc, ok := client.(FAPIProfileClient); ok && fc.FAPIProfile() {
		if responseType != protocol.ResponseTypeCode {
			return protocol.ErrUnsupportedResponseType().WithDescription("FAPI 2.0 only allows response_type=code")
		}
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

// ResolvePreferredSigningAlg returns the client's preferred signing algorithm
// for JARM authorization responses. It checks:
//  1. The client's id_token_signed_response_alg (explicit configuration)
//  2. FAPI 2.0 profile fallback: PS256 (FAPI 2.0 §5.3.2.2)
//
// Returns empty string if the client has no preference (server default will be used).
func ResolvePreferredSigningAlg(client interface{}) string {
	if algProvider, ok := client.(IDTokenSignedResponseAlgProvider); ok {
		if alg := algProvider.IDTokenSignedResponseAlg(); alg != "" {
			return alg
		}
	}
	// FAPI 2.0 §5.3.2.2: JARM responses MUST be signed with PS256 or ES256.
	if fc, ok := client.(FAPIProfileClient); ok && fc.FAPIProfile() {
		return "PS256"
	}
	return ""
}

// checkRedirectURIAgainstClient checks the URI against registered redirect URIs
// and optional glob patterns.
func checkRedirectURIAgainstClient(client AuthRequestClient, uri string) error {
	// Direct match against registered URIs.
	if rc, ok := client.(RedirectURIClient); ok {
		if slices.Contains(rc.RedirectURIs(), uri) {
			return nil
		}

		// Base URI match: if the registered URI has no query parameters,
		// match only scheme + host + path (allow extra query params in request).
		// This is common for FAPI 2.0 conformance tests.
		reqURL, reqErr := url.Parse(uri)
		if reqErr == nil {
			for _, registered := range rc.RedirectURIs() {
				regURL, regErr := url.Parse(registered)
				if regErr != nil {
					continue
				}
				if regURL.RawQuery != "" {
					// Registered URI has query params — require exact match (already checked above).
					continue
				}
				if regURL.Scheme == reqURL.Scheme &&
					regURL.Host == reqURL.Host &&
					regURL.Path == reqURL.Path {
					return nil
				}
			}
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
