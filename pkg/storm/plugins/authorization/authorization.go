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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/codec"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the OIDC Authorization endpoint.
type Plugin struct {
	authStore   storm.AuthStore
	clientStore storm.ClientStore
	crypto      storm.Crypto
	keyStore    storm.KeyStore
	converters  map[reflect.Type]codec.Converter
}

// Config holds the dependencies for the Authorization plugin.
type Config struct {
	AuthStore   storm.AuthStore
	ClientStore storm.ClientStore
	Crypto      storm.Crypto
	KeyStore    storm.KeyStore
	Converters  map[reflect.Type]codec.Converter
}

// New creates a new Authorization plugin.
func New(cfg Config) *Plugin {
	return &Plugin{
		authStore:   cfg.AuthStore,
		clientStore: cfg.ClientStore,
		crypto:      cfg.Crypto,
		keyStore:    cfg.KeyStore,
		converters:  cfg.Converters,
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
		"authorization_endpoint": shared.IssuerFromContext(ctx) + "/authorize",
	}
}

// --- authorize handler ---

func (p *Plugin) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeAuthError(w, r, "", "", oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err))
		return
	}

	authReq, err := parseAuthorizeRequest(r.Form, p.converters)
	if err != nil {
		writeAuthError(w, r, "", "", oidc.ErrInvalidRequest().WithDescription("cannot parse auth request").WithParent(err))
		return
	}

	// RFC 9101 §5.2.1: request and request_uri MUST NOT be used together.
	if authReq.RequestParam != "" && authReq.RequestURI != "" {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State,
			oidc.ErrInvalidRequest().WithDescription("request and request_uri must not be used together"))
		return
	}

	// TODO: Parse request object if present (requires JWT verification)
	// TODO: Resolve pushed authorization request if request_uri present

	if authReq.ClientID == "" {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State,
			oidc.ErrInvalidRequest().WithDescription("client_id is missing"))
		return
	}
	if authReq.RedirectURI == "" {
		// No redirect_uri means we cannot redirect; write JSON error.
		shared.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("redirect_uri is missing"), nil)
		return
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), authReq.ClientID)
	if err != nil {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State,
			oidc.ErrInvalidRequestRedirectURI().WithDescription("unable to retrieve client").WithParent(err))
		return
	}

	if err := validateAuthRequestParams(client, authReq); err != nil {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, err)
		return
	}

	// TODO: Validate id_token_hint if present (requires IDTokenHintVerifier)

	req, err := p.authStore.CreateAuthRequest(r.Context(), authReq, "")
	if err != nil {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State,
			oidc.DefaultToServerError(err, "unable to save auth request"))
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
			oidc.ErrInteractionRequired().WithDescription("user may not be logged in"))
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

	// Implicit flow: TODO - create token response directly
	writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
		oidc.ErrServerError().WithDescription("implicit flow not yet implemented"))
}

// authResponseCode handles the authorization code response.
func (p *Plugin) authResponseCode(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	code, err := createAuthRequestCode(r.Context(), authReq, p.authStore, p.crypto)
	if err != nil {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			oidc.DefaultToServerError(err, "failed to create auth code"))
		return
	}

	redirectURI := authReq.GetRedirectURI()
	u, err := url.Parse(redirectURI)
	if err != nil {
		shared.WriteError(w, r, oidc.ErrServerError().WithParent(err), nil)
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
		return oidc.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri is missing")
	}
	if _, err := url.QueryUnescape(uri); err != nil {
		return oidc.ErrInvalidRequestRedirectURI().WithDescription("invalid redirect_uri")
	}

	type redirectURIsProvider interface {
		RedirectURIs() []string
	}
	if rp, ok := client.(redirectURIsProvider); ok {
		if !slices.Contains(rp.RedirectURIs(), uri) {
			return oidc.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri not registered")
		}
	}
	return nil
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
		return oidc.ErrInvalidRequest().WithDescription("scope is missing")
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
		return oidc.ErrInvalidRequest().WithDescription("response type is missing")
	}

	type responseTypesProvider interface {
		ResponseTypes() []oidc.ResponseType
	}
	if rp, ok := client.(responseTypesProvider); ok {
		if !slices.Contains(rp.ResponseTypes(), responseType) {
			return oidc.ErrUnauthorizedClient().WithDescription("requested response type not allowed")
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
		oidcErr := oidc.DefaultToServerError(err, err.Error())
		u, parseErr := url.Parse(redirectURI)
		if parseErr == nil {
			q := u.Query()
			q.Set("error", string(oidcErr.ErrorType))
			q.Set("error_description", oidcErr.Description)
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
