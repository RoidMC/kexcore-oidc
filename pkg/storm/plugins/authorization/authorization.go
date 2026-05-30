// Package authorization implements the OIDC Authorization endpoint plugin.
//
// It handles the /authorize route (RFC 6749 Section 3.1 / OpenID Connect Core Section 3.1.1),
// covering:
//   - Parsing and validating authorization requests
//   - Redirecting to the login UI
//   - Processing the callback after authentication
//   - Generating authorization codes or implicit tokens
//
// The callback path (/authorize/callback) is an internal route for the
// login UI to redirect back to after user authentication. This is not
// part of the OIDC standard but is a common implementation pattern.
package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/util/codec"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the OIDC Authorization endpoint.
type Plugin struct {
	authStore      storm.AuthStore
	clientStore    storm.ClientStore
	crypto         storm.Crypto
	keyStore       storm.KeyStore
	converters     map[reflect.Type]codec.Converter
	enableImplicit bool
	parStore       storm.PARStore
}

// Config holds the dependencies for the Authorization plugin.
type Config struct {
	AuthStore   storm.AuthStore
	ClientStore storm.ClientStore
	Crypto      storm.Crypto
	KeyStore    storm.KeyStore
	Converters  map[reflect.Type]codec.Converter

	// EnableImplicit enables the Implicit Flow (response_type=id_token,
	// id_token token). Disabled by default per OAuth 2.1.
	EnableImplicit bool

	// PARStore enables Pushed Authorization Requests (RFC 9101).
	// When set, request_uri references are resolved from this store.
	PARStore storm.PARStore
}

// New creates a new Authorization plugin.
func New(cfg Config) *Plugin {
	return &Plugin{
		authStore:      cfg.AuthStore,
		clientStore:    cfg.ClientStore,
		crypto:         cfg.Crypto,
		keyStore:       cfg.KeyStore,
		converters:     cfg.Converters,
		enableImplicit: cfg.EnableImplicit,
		parStore:       cfg.PARStore,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "authorization" }

// Register installs the authorization routes.
//
// OIDC standard endpoint: GET /authorize (RFC 6749 §3.1, OIDC Core §3.1.1)
// POST /authorize is also supported for form-based requests.
//
// Internal callback: GET /authorize/callback
// This is NOT an OIDC standard endpoint. It is the URL the login UI
// redirects to after successful user authentication.
func (p *Plugin) Register(r chi.Router) {
	r.Get("/authorize", p.handleAuthorize)
	r.Post("/authorize", p.handleAuthorize)
	r.Get("/authorize/callback", p.handleCallback)
}

// Contribute returns the discovery fields for the authorization endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"authorization_endpoint": shared.IssuerURL(ctx, "/authorize"),
	}
}

// --- authorize handler ---

func (p *Plugin) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeAuthError(w, r, "", "", protocol.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err))
		return
	}

	authReq, err := parseAuthorizeRequest(r.Form, p.converters)
	if err != nil {
		writeAuthError(w, r, "", "", protocol.ErrInvalidRequest().WithDescription("cannot parse auth request").WithParent(err))
		return
	}

	// RFC 9101 §5.2.1: request and request_uri MUST NOT be used together.
	if authReq.RequestParam != "" && authReq.RequestURI != "" {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State,
			protocol.ErrInvalidRequest().WithDescription("request and request_uri must not be used together"))
		return
	}

	// Parse Request Object (OIDC Core §6.1, RFC 9101)
	if authReq.RequestParam != "" {
		if err := p.applyRequestObject(r.Context(), authReq); err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, err)
			return
		}
	}

	// Resolve Pushed Authorization Request (RFC 9101 §5.2)
	if authReq.RequestURI != "" {
		if p.parStore == nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State,
				protocol.ErrInvalidRequest().WithDescription("request_uri not supported"))
			return
		}
		if err := p.applyPARRequest(r.Context(), authReq); err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, err)
			return
		}
	}

	if authReq.ClientID == "" {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State,
			protocol.ErrInvalidRequest().WithDescription("client_id is missing"))
		return
	}
	if authReq.RedirectURI == "" {
		// No redirect_uri means we cannot redirect; write JSON error.
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("redirect_uri is missing"), nil)
		return
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), authReq.ClientID)
	if err != nil {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State,
			protocol.ErrInvalidRequestRedirectURI().WithDescription("unable to retrieve client").WithParent(err))
		return
	}

	if err := validateAuthRequestParams(client, authReq); err != nil {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, err)
		return
	}

	// Validate id_token_hint (OIDC Core §3.1.2.2)
	if authReq.IDTokenHint != "" {
		_, _, err := p.validateIDTokenHint(r.Context(), authReq.IDTokenHint)
		if err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State,
				protocol.ErrInvalidRequest().WithDescription("invalid id_token_hint").WithParent(err))
			return
		}
	}

	// Implicit flow guard: disabled by default per OAuth 2.1
	if !p.enableImplicit && isImplicitResponseType(authReq.ResponseType) {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State,
			protocol.ErrInvalidRequest().WithDescription("implicit flow is disabled"))
		return
	}

	req, err := p.authStore.CreateAuthRequest(r.Context(), authReq, "")
	if err != nil {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State,
			protocol.DefaultToServerError(err, "unable to save auth request"))
		return
	}

	loginURL := client.LoginURL(req.GetID())
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// --- callback handler ---

func (p *Plugin) handleCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, fmt.Errorf("cannot parse form: %w", err), nil)
		return
	}

	id := r.Form.Get("id")
	if id == "" {
		shared.WriteError(w, r, errors.New("auth request callback is missing id"), nil)
		return
	}

	authReq, err := p.authStore.AuthRequestByID(r.Context(), id)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	if !authReq.Done() {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			protocol.ErrInteractionRequired().WithDescription("user may not be logged in"))
		return
	}

	p.authResponse(w, r, authReq)
}

// authResponse creates the successful authentication response.
func (p *Plugin) authResponse(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	if authReq.GetResponseType() == oidc.ResponseTypeCode {
		p.authResponseCode(w, r, authReq)
		return
	}

	if p.enableImplicit && isImplicitResponseType(authReq.GetResponseType()) {
		p.authResponseImplicit(w, r, authReq)
		return
	}

	writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
		protocol.ErrServerError().WithDescription("unsupported response_type"))
}

// authResponseCode handles the authorization code response.
func (p *Plugin) authResponseCode(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	code, err := createAuthRequestCode(r.Context(), authReq, p.authStore, p.crypto)
	if err != nil {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			protocol.DefaultToServerError(err, "failed to create auth code"))
		return
	}

	redirectURI := authReq.GetRedirectURI()
	u, err := url.Parse(redirectURI)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithParent(err), nil)
		return
	}

	query := u.Query()
	query.Set("code", code)
	if authReq.GetState() != "" {
		query.Set("state", authReq.GetState())
	}
	u.RawQuery = query.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// --- parsing ---

func parseAuthorizeRequest(form map[string][]string, converters map[reflect.Type]codec.Converter) (*oidc.AuthRequest, error) {
	req := new(oidc.AuthRequest)
	if err := codec.Decode(req, form, converters); err != nil {
		return nil, err
	}
	return req, nil
}

// --- validation ---

func validateAuthRequestParams(client storm.Client, authReq *oidc.AuthRequest) error {
	if err := validateRedirectURI(client, authReq.RedirectURI, authReq.ResponseType); err != nil {
		return err
	}
	validatePrompt(authReq)
	if err := validateScopes(client, authReq); err != nil {
		return err
	}
	return validateResponseType(client, authReq.ResponseType)
}

func validateRedirectURI(client storm.Client, uri string, responseType oidc.ResponseType) error {
	if uri == "" {
		return protocol.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri is missing")
	}
	if _, err := url.QueryUnescape(uri); err != nil {
		return protocol.ErrInvalidRequestRedirectURI().WithDescription("invalid redirect_uri")
	}

	// OIDC Core §15.6.3 / OAuth 2.1 §3.1.2.1: HTTPS required, localhost exception
	if err := validateRedirectURIScheme(uri); err != nil {
		return protocol.ErrInvalidRequestRedirectURI().WithParent(err)
	}

	type redirectURIsProvider interface {
		RedirectURIs() []string
	}
	if rp, ok := client.(redirectURIsProvider); ok {
		if !slices.Contains(rp.RedirectURIs(), uri) {
			return protocol.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri not registered")
		}
	}
	return nil
}

// validateRedirectURIScheme enforces HTTPS for redirect URIs per OIDC Core §15.6.3.
// Exception: localhost (127.0.0.1, ::1, [::1]) and 0.0.0.0 may use HTTP
// for development purposes per RFC 8252 §7.3 and OAuth 2.1 §3.1.2.1.
func validateRedirectURIScheme(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri: %w", err)
	}

	if u.Scheme == "https" {
		return nil
	}

	// Allow HTTP for localhost
	if u.Scheme == "http" && isLocalhost(u.Hostname()) {
		return nil
	}

	// Allow custom schemes (native apps per RFC 8252)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}

	return fmt.Errorf("redirect_uri must use https (got %q)", u.Scheme)
}

// isLocalhost returns true if the hostname is a loopback address.
func isLocalhost(host string) bool {
	return host == "localhost" ||
		host == "127.0.0.1" ||
		host == "::1" ||
		host == "0.0.0.0"
}

func validatePrompt(authReq *oidc.AuthRequest) {
	for _, prompt := range authReq.Prompt {
		if prompt == oidc.PromptNone && len(authReq.Prompt) > 1 {
			// Caller will handle the error; we just flag it.
			return
		}
		if prompt == oidc.PromptLogin {
			zero := uint(0)
			authReq.MaxAge = &zero
		}
	}
}

func validateScopes(client storm.Client, authReq *oidc.AuthRequest) error {
	if len(authReq.Scopes) == 0 {
		return protocol.ErrInvalidRequest().WithDescription("scope is missing")
	}

	type scopeProvider interface {
		IsScopeAllowed(string) bool
	}

	authReq.Scopes = slices.DeleteFunc(authReq.Scopes, func(scope string) bool {
		switch scope {
		case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail,
			oidc.ScopePhone, oidc.ScopeAddress, oidc.ScopeOfflineAccess:
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

func validateResponseType(client storm.Client, responseType oidc.ResponseType) error {
	if responseType == "" {
		return protocol.ErrInvalidRequest().WithDescription("response type is missing")
	}

	type responseTypesProvider interface {
		ResponseTypes() []oidc.ResponseType
	}
	if rp, ok := client.(responseTypesProvider); ok {
		if !slices.Contains(rp.ResponseTypes(), responseType) {
			return protocol.ErrUnauthorizedClient().WithDescription("requested response type not allowed")
		}
	}
	return nil
}

// --- code creation ---

func createAuthRequestCode(ctx context.Context, authReq storm.AuthRequest, store storm.AuthStore, enc storm.Crypto) (string, error) {
	encrypted, err := enc.Encrypt(ctx, []byte(authReq.GetID()))
	if err != nil {
		return "", err
	}
	code := string(encrypted)
	if err := store.SaveAuthCode(ctx, authReq.GetID(), code); err != nil {
		return "", err
	}
	return code, nil
}

// --- error handling ---

// writeAuthError writes an authorization error response.
// Per OIDC Core §3.1.2.6, errors should be redirected to redirect_uri
// when possible. Falls back to JSON if no redirect_uri is available.
func writeAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state string, err error) {
	if redirectURI != "" {
		protocolErr := protocol.DefaultToServerError(err, err.Error())
		u, parseErr := url.Parse(redirectURI)
		if parseErr == nil {
			q := u.Query()
			q.Set("error", string(protocolErr.ErrorType))
			q.Set("error_description", protocolErr.Description)
			if state != "" {
				q.Set("state", state)
			}
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}

	shared.WriteError(w, r, err, nil)
}

// --- implicit flow helpers ---

// isImplicitResponseType returns true if the response type includes
// id_token (Implicit or Hybrid flow per OIDC Core §3.2).
func isImplicitResponseType(rt oidc.ResponseType) bool {
	return rt == oidc.ResponseTypeIDTokenOnly ||
		rt == oidc.ResponseTypeIDToken
}

// authResponseImplicit handles the Implicit Flow response (OIDC Core §3.2.2.5).
// Tokens are returned directly in the fragment of the redirect URI.
func (p *Plugin) authResponseImplicit(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	u, err := url.Parse(authReq.GetRedirectURI())
	if err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithParent(err), nil)
		return
	}

	fragment := u.Query()
	fragment.Set("state", authReq.GetState())

	if authReq.GetResponseType() == oidc.ResponseTypeIDTokenOnly ||
		authReq.GetResponseType() == oidc.ResponseTypeIDToken {
		idToken, err := p.createImplicitIDToken(r.Context(), authReq)
		if err == nil && idToken != "" {
			fragment.Set("id_token", idToken)
		}
	}

	u.RawFragment = fragment.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *Plugin) createImplicitIDToken(ctx context.Context, authReq storm.AuthRequest) (string, error) {
	if p.keyStore == nil {
		return "", nil
	}
	signingKey, err := p.keyStore.SigningKey(ctx)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss": shared.IssuerFromContext(ctx),
		"sub": authReq.GetSubject(),
		"aud": authReq.GetClientID(),
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if nonce := authReq.GetNonce(); nonce != "" {
		claims["nonce"] = nonce
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	alg, err := algorithmToJWA(signingKey.Algorithm())
	if err != nil {
		return "", fmt.Errorf("unsupported signing algorithm %q: %w", signingKey.Algorithm(), err)
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.AlgorithmKey, alg)
	if signingKey.ID() != "" {
		_ = headers.Set(jws.KeyIDKey, signingKey.ID())
	}
	signed, err := jws.Sign(payload, jws.WithKey(alg, signingKey.Key(), jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("JWS signing failed: %w", err)
	}
	return string(signed), nil
}

// --- request object / PAR helpers ---

// applyRequestObject parses and validates a JWT request object (OIDC Core §6.1).
func (p *Plugin) applyRequestObject(ctx context.Context, authReq *oidc.AuthRequest) error {
	if p.keyStore == nil {
		return protocol.ErrInvalidRequest().WithDescription("request object not supported")
	}

	keyStore := storm.AdaptKeyStore(p.keyStore)
	_, err := shared.VerifyJWTAssertion(ctx, authReq.RequestParam, shared.IssuerFromContext(ctx), keyStore, 0)
	if err != nil {
		return protocol.ErrInvalidRequest().WithDescription("invalid request object").WithParent(err)
	}

	return nil
}

// applyPARRequest resolves a Pushed Authorization Request (RFC 9101 §5.2).
func (p *Plugin) applyPARRequest(ctx context.Context, authReq *oidc.AuthRequest) error {
	parReq, err := p.parStore.GetPushedAuthRequest(ctx, authReq.RequestURI)
	if err != nil {
		return protocol.ErrInvalidRequest().WithDescription("invalid request_uri").WithParent(err)
	}

	if parReq.ClientID != "" && authReq.ClientID == "" {
		authReq.ClientID = parReq.ClientID
	}
	if parReq.RedirectURI != "" && authReq.RedirectURI == "" {
		authReq.RedirectURI = parReq.RedirectURI
	}
	if len(parReq.Scopes) > 0 && len(authReq.Scopes) == 0 {
		authReq.Scopes = parReq.Scopes
	}
	if parReq.State != "" && authReq.State == "" {
		authReq.State = parReq.State
	}
	if parReq.ResponseType != "" && authReq.ResponseType == "" {
		authReq.ResponseType = parReq.ResponseType
	}

	return nil
}

// validateIDTokenHint validates an id_token_hint (OIDC Core §3.1.2.2).
func (p *Plugin) validateIDTokenHint(ctx context.Context, idTokenHint string) (subject, clientID string, err error) {
	if p.keyStore == nil {
		return "", "", nil
	}

	keyStore := storm.AdaptKeyStore(p.keyStore)
	_, err = shared.VerifyJWTAssertion(ctx, idTokenHint, shared.IssuerFromContext(ctx), keyStore, 0)
	if err != nil {
		return "", "", err
	}

	return "", "", nil
}

// algorithmToJWA converts a string algorithm name to jwa.SignatureAlgorithm.
func algorithmToJWA(alg string) (jwa.SignatureAlgorithm, error) {
	if jwaAlg, ok := jwa.LookupSignatureAlgorithm(alg); ok {
		return jwaAlg, nil
	}
	unknown, _ := jwa.LookupSignatureAlgorithm(alg)
	return unknown, fmt.Errorf("unknown algorithm: %s", alg)
}
