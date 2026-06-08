package authorization

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"

	crypto_pkg "github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// --- URL / host helpers ---

// httpLoopbackOrLocalhost parses a URL and returns true if it uses HTTP/HTTPS
// and points to a loopback address.
func httpLoopbackOrLocalhost(rawURL string) (*url.URL, bool) {
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

// equalURI returns true if two URLs have the same path and raw query.
func equalURI(url1, url2 *url.URL) bool {
	if url1 == nil || url2 == nil {
		return false
	}
	return url1.Path == url2.Path && url1.RawQuery == url2.RawQuery
}

// isLocalhost returns true if the hostname is a loopback address.
// Per RFC 8252 §7.3, only 127.0.0.1 and ::1 are loopback addresses.
// 0.0.0.0 is the wildcard address and is NOT a loopback address.
func isLocalhost(host string) bool {
	return host == "localhost" ||
		host == "127.0.0.1" ||
		host == "::1"
}

// --- parsing ---

func parseAuthorizeRequest(form map[string][]string, decoder *protocol.Decoder) (*protocol.AuthRequest, error) {
	req := new(protocol.AuthRequest)
	if err := decoder.Decode(req, form); err != nil {
		return nil, err
	}
	return req, nil
}

// --- validation ---

func validateAuthRequestParams(client storm.Client, authReq *protocol.AuthRequest) error {
	if err := validateRedirectURI(client, authReq.RedirectURI, authReq.ResponseType); err != nil {
		return err
	}
	return validateAuthRequestParamsExceptRedirectURI(client, authReq)
}

// validateAuthRequestParamsExceptRedirectURI validates all params except redirect_uri.
// This is called after redirect_uri has been validated separately, so that
// remaining errors can be safely redirected to the registered URI.
func validateAuthRequestParamsExceptRedirectURI(client storm.Client, authReq *protocol.AuthRequest) error {
	if err := validatePrompt(authReq); err != nil {
		return err
	}
	if err := validateScopes(client, authReq); err != nil {
		return err
	}
	if err := validatePKCE(authReq); err != nil {
		return err
	}
	if err := validateNonce(authReq); err != nil {
		return err
	}
	return validateResponseType(client, authReq.ResponseType)
}

func validateRedirectURI(client storm.Client, uri string, responseType protocol.ResponseType) error {
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

func validateRedirectURIWeb(client storm.Client, uri string, responseType protocol.ResponseType) error {
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
	if u.Scheme == "http" && isLocalhost(u.Hostname()) {
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

func validateRedirectURINative(client storm.Client, uri string, responseType protocol.ResponseType) error {
	u, err := url.Parse(uri)
	if err != nil {
		return protocol.ErrInvalidRequestRedirectURI().WithDescription("invalid redirect_uri")
	}

	parsedURL, isLoopback := httpLoopbackOrLocalhost(uri)
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
			redirectURI, ok := httpLoopbackOrLocalhost(registered)
			if ok && equalURI(parsedURL, redirectURI) {
				return nil
			}
		}
	}

	return protocol.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri not registered")
}

// checkRedirectURIAgainstClient checks the URI against registered redirect URIs
// and optional glob patterns.
func checkRedirectURIAgainstClient(client storm.Client, uri string) error {
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

// validatePrompt validates the prompt parameter and mutates authReq accordingly.
// Per OIDC Core §3.1.2.1:
//   - "none" MUST NOT be combined with other values.
//   - "login" forces re-authentication by setting max_age to 0.
//   - "consent" and "select_account" are recognized but their enforcement
//     depends on the login UI implementation.
func validatePrompt(authReq *protocol.AuthRequest) error {
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

func validateScopes(client storm.Client, authReq *protocol.AuthRequest) error {
	if len(authReq.Scopes) == 0 {
		return protocol.ErrInvalidRequest().WithDescription("scope is missing")
	}

	type scopeProvider interface {
		IsScopeAllowed(string) bool
	}

	// Determine strict mode: client can opt-in via ScopeValidationClient.
	strict := false
	if svc, ok := client.(storm.ScopeValidationClient); ok {
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

func validateResponseType(client storm.Client, responseType protocol.ResponseType) error {
	if responseType == "" {
		return protocol.ErrInvalidRequest().WithDescription("response type is missing")
	}

	type responseTypesProvider interface {
		ResponseTypes() []protocol.ResponseType
	}
	if rp, ok := client.(responseTypesProvider); ok {
		allowed := rp.ResponseTypes()
		// An empty/nil list means no restriction (all types allowed).
		if len(allowed) > 0 && !slices.Contains(allowed, responseType) {
			return protocol.ErrUnauthorizedClient().WithDescription("requested response type not allowed")
		}
	}
	return nil
}

// validatePKCE checks that code_challenge_method is valid when code_challenge is present.
func validatePKCE(authReq *protocol.AuthRequest) error {
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

// validateNonce enforces that nonce is present for implicit flows (OIDC Core §3.2.2.1).
func validateNonce(authReq *protocol.AuthRequest) error {
	if authReq.ResponseType == protocol.ResponseTypeIDTokenOnly ||
		authReq.ResponseType == protocol.ResponseTypeIDToken {
		if authReq.Nonce == "" {
			return protocol.ErrInvalidRequest().
				WithDescription("nonce is required for implicit flow")
		}
	}
	return nil
}

// --- code creation ---

func createAuthRequestCode(ctx context.Context, authReq storm.AuthRequest, store storm.AuthStore, enc storm.UniCrypto) (string, error) {
	encrypted, err := enc.Encrypt(ctx, []byte(authReq.GetID()))
	if err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(encrypted)
	if err := store.SaveAuthCode(ctx, authReq.GetID(), code); err != nil {
		return "", err
	}
	return code, nil
}

// --- error handling ---

// writeAuthError writes an authorization error response.
// Per OIDC Core §3.1.2.6, errors should be redirected to redirect_uri
// when possible. Falls back to JSON if no redirect_uri is available.
// The error response uses the same response_mode as the successful response
// per OAuth 2.0 Multiple Response Types §2.1 and OIDC Core §3.1.2.6.
func writeAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state string, responseMode protocol.ResponseMode, err error) {
	if redirectURI == "" {
		shared.WriteError(w, r, err, nil)
		return
	}

	protocolErr := protocol.DefaultToServerError(err, err.Error())
	u, parseErr := url.Parse(redirectURI)
	if parseErr != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	params := url.Values{}
	params.Set("error", string(protocolErr.ErrorType))
	params.Set("error_description", protocolErr.Description)
	if state != "" {
		params.Set("state", state)
	}

	switch responseMode {
	case protocol.ResponseModeFragment:
		// Build fragment URL manually: strip any existing fragment from the
		// base URL and append the new fragment parameters.
		base := redirectURI
		if idx := strings.Index(base, "#"); idx >= 0 {
			base = base[:idx]
		}
		http.Redirect(w, r, base+"#"+params.Encode(), http.StatusFound)
		return
	case protocol.ResponseModeFormPost:
		if formPostErr := writeFormPostError(w, redirectURI, params); formPostErr != nil {
			shared.WriteError(w, r, err, nil)
		}
		return
	default:
		// Default: query (per OIDC Core §3.1.2.6 for Authorization Code Flow)
		q := u.Query()
		for key, vals := range params {
			for _, val := range vals {
				q.Add(key, val)
			}
		}
		u.RawQuery = q.Encode()
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// writeFormPostError writes an error response using form_post response mode.
func writeFormPostError(w http.ResponseWriter, redirectURI string, params url.Values) error {
	values := make(map[string][]string)
	for key, vals := range params {
		values[key] = vals
	}

	tmplParams := &struct {
		RedirectURI string
		Params      map[string][]string
	}{
		RedirectURI: redirectURI,
		Params:      values,
	}

	var buf bytes.Buffer
	if err := formPostTmpl.Execute(&buf, tmplParams); err != nil {
		return err
	}

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
	return nil
}

// --- implicit flow helpers ---

// isImplicitResponseType returns true if the response type is an implicit flow
// (id_token only or id_token token). Does NOT include hybrid flows.
func isImplicitResponseType(rt protocol.ResponseType) bool {
	return rt == protocol.ResponseTypeIDTokenOnly ||
		rt == protocol.ResponseTypeIDToken
}

// isHybridResponseType returns true if the response type is a hybrid flow
// (code id_token, code token, or code id_token token).
func isHybridResponseType(rt protocol.ResponseType) bool {
	return rt == protocol.ResponseTypeCodeIDToken ||
		rt == protocol.ResponseTypeCodeToken ||
		rt == protocol.ResponseTypeCodeIDTokenToken
}

// usesFragmentDefault returns true if the response type defaults to fragment
// response mode per OAuth 2.0 Multiple Response Types §2.1.
// Pure code flow uses query; all others (implicit + hybrid) use fragment.
func usesFragmentDefault(rt protocol.ResponseType) bool {
	return rt != protocol.ResponseTypeCode
}

// resolveResponseMode returns the effective response mode.
// If the explicit response mode is set, it is returned as-is.
// Otherwise, the default is determined by the response type:
//   - code flow → query
//   - implicit/hybrid flows → fragment
func resolveResponseMode(explicit protocol.ResponseMode, rt protocol.ResponseType) protocol.ResponseMode {
	if explicit != "" {
		return explicit
	}
	if usesFragmentDefault(rt) {
		return protocol.ResponseModeFragment
	}
	return protocol.ResponseModeQuery
}

// --- request object helpers ---

// copyRequestObjectToAuthRequest overwrites present values from the Request Object
// into the auth request and clears the RequestParam.
// Per OIDC Core §6.1, Request Object parameters override the top-level parameters.
func copyRequestObjectToAuthRequest(authReq *protocol.AuthRequest, requestObject *protocol.RequestObject) {
	if len(requestObject.Scopes) > 0 {
		authReq.Scopes = requestObject.Scopes
	}
	if requestObject.RedirectURI != "" {
		authReq.RedirectURI = requestObject.RedirectURI
	}
	if requestObject.State != "" {
		authReq.State = requestObject.State
	}
	if requestObject.ResponseMode != "" {
		authReq.ResponseMode = requestObject.ResponseMode
	}
	if requestObject.Nonce != "" {
		authReq.Nonce = requestObject.Nonce
	}
	if requestObject.Display != "" {
		authReq.Display = requestObject.Display
	}
	if len(requestObject.Prompt) > 0 {
		authReq.Prompt = requestObject.Prompt
	}
	if requestObject.MaxAge != nil {
		authReq.MaxAge = requestObject.MaxAge
	}
	if len(requestObject.UILocales) > 0 {
		authReq.UILocales = requestObject.UILocales
	}
	if requestObject.IDTokenHint != "" {
		authReq.IDTokenHint = requestObject.IDTokenHint
	}
	if requestObject.LoginHint != "" {
		authReq.LoginHint = requestObject.LoginHint
	}
	if len(requestObject.ACRValues) > 0 {
		authReq.ACRValues = requestObject.ACRValues
	}
	if requestObject.CodeChallenge != "" {
		authReq.CodeChallenge = requestObject.CodeChallenge
	}
	if requestObject.CodeChallengeMethod != "" {
		authReq.CodeChallengeMethod = requestObject.CodeChallengeMethod
	}
	authReq.RequestParam = ""
}

// --- algorithm helpers ---

// algorithmToJWA converts a string algorithm name to jwa.SignatureAlgorithm.
func algorithmToJWA(alg string) (jwa.SignatureAlgorithm, error) {
	jwaAlg, ok := jwa.LookupSignatureAlgorithm(alg)
	if !ok {
		return jwaAlg, fmt.Errorf("unsupported signing algorithm %q", alg)
	}
	return jwaAlg, nil
}

// hashTokenForIDToken computes the at_hash or c_hash claim value
// per OIDC Core §2 (ID Token) and §3.2.2.1 (Implicit Flow).
//
// The hash is the base64url encoding of the left half of the hash of the token.
//
// Uses UniCrypto.Hash for unified hash computation. If crypto is nil,
// falls back to local computation using pkg/crypto.
func hashTokenForIDToken(token string, sigAlg string, crypto storm.UniCrypto) string {
	if crypto != nil {
		hashBytes, err := crypto.Hash(context.Background(), sigAlg, []byte(token))
		if err == nil && len(hashBytes) > 0 {
			// Take left half and base64url encode
			halfLen := len(hashBytes) / 2
			return base64.RawURLEncoding.EncodeToString(hashBytes[:halfLen])
		}
		// Fall through to local computation on error
	}

	// Fallback to local computation
	h, err := crypto_pkg.GetHashAlgorithm(sigAlg)
	if err != nil {
		return ""
	}
	return crypto_pkg.HashString(h, token, true)
}
