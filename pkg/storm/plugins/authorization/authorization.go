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
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jws"

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
	tokenStore     storm.TokenStore
	decoder        *protocol.Decoder
	enableImplicit bool
	parStore       storm.PARStore
}

//go:embed template/form_post.html.tmpl
var formPostHtmlTemplate string

var formPostTmpl = template.Must(template.New("form_post").Parse(formPostHtmlTemplate))

// Config holds the dependencies for the Authorization plugin.
type Config struct {
	AuthStore   storm.AuthStore
	ClientStore storm.ClientStore
	Crypto      storm.Crypto
	KeyStore    storm.KeyStore
	TokenStore  storm.TokenStore
	Decoder     *protocol.Decoder

	// EnableImplicit enables the Implicit Flow (response_type=id_token,
	// id_token token). Disabled by default per OAuth 2.1.
	EnableImplicit bool

	// PARStore enables Pushed Authorization Requests (RFC 9101).
	// When set, request_uri references are resolved from this store.
	PARStore storm.PARStore
}

// New creates a new Authorization plugin from a PluginContext.
// Storage must implement AuthStore, ClientStore, and KeyStore.
// If Storage also implements TokenStore, it is used for Implicit Flow
// access token generation. If Storage implements PARStore, Pushed
// Authorization Requests are enabled.
func New(ctx *storm.PluginContext) *Plugin {
	p := &Plugin{
		authStore:   ctx.Storage.(storm.AuthStore),
		clientStore: ctx.Storage.(storm.ClientStore),
		crypto:      ctx.Crypto,
		keyStore:    ctx.Storage.(storm.KeyStore),
		decoder:     ctx.Decoder,
	}
	// Optionally extract TokenStore and PARStore from storage.
	if ts, ok := ctx.Storage.(storm.TokenStore); ok {
		p.tokenStore = ts
	}
	if ps, ok := ctx.Storage.(storm.PARStore); ok {
		p.parStore = ps
	}
	return p
}

// NewWithConfig creates a new Authorization plugin with explicit config.
// Use this when you need to override defaults (e.g., enable implicit flow).
func NewWithConfig(cfg Config) *Plugin {
	return &Plugin{
		authStore:      cfg.AuthStore,
		clientStore:    cfg.ClientStore,
		crypto:         cfg.Crypto,
		keyStore:       cfg.KeyStore,
		tokenStore:     cfg.TokenStore,
		decoder:        cfg.Decoder,
		enableImplicit: cfg.EnableImplicit,
		parStore:       cfg.PARStore,
	}
}

// init self-registers the authorization plugin in the global registry.
func init() {
	storm.RegisterPlugin("authorization", storm.PriorityAuthorization, func(ctx *storm.PluginContext) storm.Plugin {
		return New(ctx)
	})
}

// Category returns CategoryCore — authorization is a required OAuth 2.0 endpoint.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryCore }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string {
	return []string{"AuthStore", "ClientStore", "KeyStore"}
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
		writeAuthError(w, r, "", "", "", protocol.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err))
		return
	}

	authReq, err := parseAuthorizeRequest(r.Form, p.decoder)
	if err != nil {
		writeAuthError(w, r, "", "", "", protocol.ErrInvalidRequest().WithDescription("cannot parse auth request").WithParent(err))
		return
	}

	// RFC 9101 §5.2.1: request and request_uri MUST NOT be used together.
	// Note: Before the client is resolved, we cannot validate redirect_uri
	// against registered URIs. Per OIDC Core §3.1.2.6, we must not redirect
	// errors to an unvalidated redirect_uri. These early errors are shown
	// directly to the user.
	if authReq.RequestParam != "" && authReq.RequestURI != "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("request and request_uri must not be used together"), nil)
		return
	}

	// Parse Request Object (OIDC Core §6.1, RFC 9101)
	if authReq.RequestParam != "" {
		if err := p.applyRequestObject(r.Context(), authReq); err != nil {
			shared.WriteError(w, r, err, nil)
			return
		}
	}

	// Resolve Pushed Authorization Request (RFC 9101 §5.2)
	if authReq.RequestURI != "" {
		if p.parStore == nil {
			shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("request_uri not supported"), nil)
			return
		}
		if err := p.applyPARRequest(r.Context(), authReq); err != nil {
			shared.WriteError(w, r, err, nil)
			return
		}
	}

	if authReq.ClientID == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("client_id is missing"), nil)
		return
	}
	if authReq.RedirectURI == "" {
		// No redirect_uri means we cannot redirect; write JSON error.
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("redirect_uri is missing"), nil)
		return
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), authReq.ClientID)
	if err != nil {
		// Client not found: cannot validate redirect_uri, so do not redirect.
		shared.WriteError(w, r, protocol.ErrInvalidRequestRedirectURI().WithDescription("unable to retrieve client").WithParent(err), nil)
		return
	}

	if err := validateAuthRequestParams(client, authReq); err != nil {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, authReq.ResponseMode, err)
		return
	}

	// Validate id_token_hint (OIDC Core §3.1.2.2)
	if authReq.IDTokenHint != "" {
		_, _, err := p.validateIDTokenHint(r.Context(), authReq.IDTokenHint)
		if err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, authReq.ResponseMode,
				protocol.ErrInvalidRequest().WithDescription("invalid id_token_hint").WithParent(err))
			return
		}
		// Note: subject matching is delegated to the login UI, which can
		// re-parse the id_token_hint to extract the sub claim and compare
		// it against the authenticated user. Per OIDC Core §3.1.2.2, if
		// the identified user does not match, the OP SHOULD return an error.
	}

	// Implicit flow guard: disabled by default per OAuth 2.1
	if !p.enableImplicit && isImplicitResponseType(authReq.ResponseType) {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, authReq.ResponseMode,
			protocol.ErrInvalidRequest().WithDescription("implicit flow is disabled"))
		return
	}

	// Invoke AuthorizeValidator extension point if client implements it.
	if avc, ok := client.(AuthorizeValidatorClient); ok {
		if err := avc.AuthorizeValidator().ValidateAuthRequest(client, authReq); err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, authReq.ResponseMode, err)
			return
		}
	}

	req, err := p.authStore.CreateAuthRequest(r.Context(), authReq, "")
	if err != nil {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, authReq.ResponseMode,
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
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(), authReq.GetResponseMode(),
			protocol.ErrInteractionRequired().WithDescription("user may not be logged in"))
		return
	}

	p.authResponse(w, r, authReq)
}

// authResponse creates the successful authentication response.
func (p *Plugin) authResponse(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	if authReq.GetResponseType() == protocol.ResponseTypeCode {
		p.authResponseCode(w, r, authReq)
		return
	}

	if p.enableImplicit && isImplicitResponseType(authReq.GetResponseType()) {
		p.authResponseImplicit(w, r, authReq)
		return
	}

	writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(), authReq.GetResponseMode(),
		protocol.ErrServerError().WithDescription("unsupported response_type"))
}

// authResponseCode handles the authorization code response.
func (p *Plugin) authResponseCode(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	code, err := createAuthRequestCode(r.Context(), authReq, p.authStore, p.crypto)
	if err != nil {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(), authReq.GetResponseMode(),
			protocol.DefaultToServerError(err, "failed to create auth code"))
		return
	}

	redirectURI := authReq.GetRedirectURI()
	responseMode := authReq.GetResponseMode()

	// Build response payload.
	resp := &codeResponse{
		Code:  code,
		State: authReq.GetState(),
	}

	// Include session_state if client supports it.
	if ssc, ok := authReq.(SessionStateClient); ok {
		resp.SessionState = ssc.GetSessionState()
	}

	// Form Post response mode (OIDC Core §3.1.2.5 / §3.3.2.5)
	if responseMode == protocol.ResponseModeFormPost {
		if err := writeFormPostResponse(w, redirectURI, resp); err != nil {
			writeAuthError(w, r, redirectURI, authReq.GetState(), authReq.GetResponseMode(), err)
		}
		return
	}

	// Redirect response (query or fragment).
	u, err := url.Parse(redirectURI)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithParent(err), nil)
		return
	}

	params := url.Values{}
	params.Set("code", resp.Code)
	if resp.State != "" {
		params.Set("state", resp.State)
	}
	if resp.SessionState != "" {
		params.Set("session_state", resp.SessionState)
	}

	// Determine where to place parameters based on response_mode.
	// Per OIDC Core §3.1.2.5 / OAuth 2.0 Multiple Response Types:
	// - explicit query mode -> query
	// - explicit fragment mode -> fragment
	// - default for code flow -> query
	switch responseMode {
	case protocol.ResponseModeFragment:
		u.Fragment = params.Encode()
	case protocol.ResponseModeQuery:
		u.RawQuery = params.Encode()
	default:
		// Default for code flow: query parameters.
		queries := u.Query()
		for key, vals := range params {
			for _, val := range vals {
				queries.Add(key, val)
			}
		}
		u.RawQuery = queries.Encode()
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// writeFormPostResponse writes an HTML form that auto-submits the response.
func writeFormPostResponse(w http.ResponseWriter, redirectURI string, response *codeResponse) error {
	values := make(map[string][]string)
	if response.Code != "" {
		values["code"] = []string{response.Code}
	}
	if response.State != "" {
		values["state"] = []string{response.State}
	}
	if response.SessionState != "" {
		values["session_state"] = []string{response.SessionState}
	}

	params := &struct {
		RedirectURI string
		Params      map[string][]string
	}{
		RedirectURI: redirectURI,
		Params:      values,
	}

	var buf bytes.Buffer
	if err := formPostTmpl.Execute(&buf, params); err != nil {
		return protocol.ErrServerError().WithParent(err)
	}

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
	return nil
}

// --- parsing ---

// parseAuthorizeRequest, validateAuthRequestParams, validateRedirectURI,
// validateRedirectURIWeb, validateRedirectURINative, checkRedirectURIAgainstClient,
// validatePrompt, validateScopes, validateResponseType, createAuthRequestCode,
// validatePKCE, validateNonce, writeAuthError, writeFormPostError,
// isImplicitResponseType, copyRequestObjectToAuthRequest, and algorithmToJWA
// are defined in util.go.

// --- implicit flow ---

// authResponseImplicit handles the Implicit Flow response (OIDC Core §3.2.2.5).
// Tokens are returned directly in the fragment of the redirect URI.
// Per OIDC Core §3.2.2.5:
//   - response_type=id_token: returns only id_token
//   - response_type=id_token token: returns access_token, token_type, and id_token
func (p *Plugin) authResponseImplicit(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	if _, err := url.Parse(authReq.GetRedirectURI()); err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithParent(err), nil)
		return
	}

	fragment := url.Values{}
	fragment.Set("state", authReq.GetState())

	// OIDC Core §3.2.2.5: response_type=id_token token MUST return access_token.
	if authReq.GetResponseType() == protocol.ResponseTypeIDToken {
		accessToken, expiresIn, err := p.createImplicitAccessToken(r.Context(), authReq)
		if err == nil && accessToken != "" {
			fragment.Set("access_token", accessToken)
			fragment.Set("token_type", protocol.BearerToken)
			if expiresIn > 0 {
				fragment.Set("expires_in", fmt.Sprintf("%d", expiresIn))
			}
		}
	}

	if authReq.GetResponseType() == protocol.ResponseTypeIDTokenOnly ||
		authReq.GetResponseType() == protocol.ResponseTypeIDToken {
		idToken, err := p.createImplicitIDToken(r.Context(), authReq)
		if err == nil && idToken != "" {
			fragment.Set("id_token", idToken)
		}
	}

	// Build fragment URL manually (Go 1.22+ u.RawFragment may not be
	// reflected in u.String() when u.Fragment is also set by url.Parse).
	redirectURL := authReq.GetRedirectURI()
	if idx := strings.Index(redirectURL, "#"); idx >= 0 {
		redirectURL = redirectURL[:idx]
	}
	redirectURL += "#" + fragment.Encode()

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// createImplicitAccessToken creates an access token for the Implicit Flow.
// Per OIDC Core §3.2.2.5, access_token is returned when response_type includes "token".
func (p *Plugin) createImplicitAccessToken(ctx context.Context, authReq storm.AuthRequest) (string, uint64, error) {
	if p.tokenStore == nil || p.crypto == nil {
		return "", 0, nil
	}

	tokenID, expiration, err := p.tokenStore.CreateAccessToken(ctx, authReq)
	if err != nil {
		return "", 0, err
	}

	plaintext := []byte(tokenID + ":" + authReq.GetSubject())
	encrypted, err := p.crypto.Encrypt(ctx, plaintext)
	if err != nil {
		return "", 0, err
	}

	validity := expiration.Sub(time.Now().UTC())
	expiresIn := uint64(validity.Seconds())
	return string(encrypted), expiresIn, nil
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
func (p *Plugin) applyRequestObject(ctx context.Context, authReq *protocol.AuthRequest) error {
	if p.keyStore == nil {
		return protocol.ErrInvalidRequest().WithDescription("request object not supported")
	}

	requestObject := new(protocol.RequestObject)
	payload, err := protocol.ParseToken(authReq.RequestParam, requestObject)
	if err != nil {
		return protocol.ErrInvalidRequest().WithDescription("invalid request object").WithParent(err)
	}

	// Validate request object claims against the auth request.
	if requestObject.ClientID != "" && requestObject.ClientID != authReq.ClientID {
		return protocol.ErrInvalidRequest().WithDescription("missing or wrong client id in request object")
	}
	if requestObject.ResponseType != "" && requestObject.ResponseType != authReq.ResponseType {
		return protocol.ErrInvalidRequest().WithDescription("missing or wrong response type in request object")
	}
	if requestObject.Issuer != requestObject.ClientID {
		return protocol.ErrInvalidRequest().WithDescription("missing or wrong issuer in request object")
	}
	issuer := shared.IssuerFromContext(ctx)
	if !slices.Contains(requestObject.Audience, issuer) {
		return protocol.ErrInvalidRequest().WithDescription("issuer missing in request object audience")
	}

	// Verify signature using the key store.
	if err = protocol.CheckSignatureWithKeyStore(ctx, authReq.RequestParam, payload, requestObject, nil, p.keyStore); err != nil {
		return protocol.ErrInvalidRequest().WithDescription("invalid request object signature").WithParent(err)
	}

	// Copy request object values into the auth request.
	copyRequestObjectToAuthRequest(authReq, requestObject)
	return nil
}

// applyPARRequest resolves a Pushed Authorization Request (RFC 9101 §5.2).
func (p *Plugin) applyPARRequest(ctx context.Context, authReq *protocol.AuthRequest) error {
	parReq, err := p.parStore.GetPushedAuthRequest(ctx, authReq.RequestURI)
	if err != nil {
		return protocol.ErrInvalidRequest().WithDescription("invalid request_uri").WithParent(err)
	}

	// Only copy fields that are not already present in the incoming request.
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
	if parReq.ResponseMode != "" && authReq.ResponseMode == "" {
		authReq.ResponseMode = parReq.ResponseMode
	}
	if parReq.Nonce != "" && authReq.Nonce == "" {
		authReq.Nonce = parReq.Nonce
	}
	if parReq.Display != "" && authReq.Display == "" {
		authReq.Display = parReq.Display
	}
	if len(parReq.Prompt) > 0 && len(authReq.Prompt) == 0 {
		authReq.Prompt = parReq.Prompt
	}
	if parReq.MaxAge != nil && authReq.MaxAge == nil {
		authReq.MaxAge = parReq.MaxAge
	}
	if len(parReq.UILocales) > 0 && len(authReq.UILocales) == 0 {
		authReq.UILocales = parReq.UILocales
	}
	if parReq.IDTokenHint != "" && authReq.IDTokenHint == "" {
		authReq.IDTokenHint = parReq.IDTokenHint
	}
	if parReq.LoginHint != "" && authReq.LoginHint == "" {
		authReq.LoginHint = parReq.LoginHint
	}
	if len(parReq.ACRValues) > 0 && len(authReq.ACRValues) == 0 {
		authReq.ACRValues = parReq.ACRValues
	}
	if parReq.CodeChallenge != "" && authReq.CodeChallenge == "" {
		authReq.CodeChallenge = parReq.CodeChallenge
	}
	if parReq.CodeChallengeMethod != "" && authReq.CodeChallengeMethod == "" {
		authReq.CodeChallengeMethod = parReq.CodeChallengeMethod
	}

	return nil
}

// validateIDTokenHint validates an id_token_hint (OIDC Core §3.1.2.2).
// It uses protocol.VerifyIDTokenHint to verify the token and extract claims.
// Returns the subject and client ID (from aud) for caller-side subject matching.
// Per OIDC Core §3.1.2.2: "If the End-User identified by the ID Token
// is logged in or is logged in by the request, then the Authorization Server
// returns a positive response; otherwise, it SHOULD return an error."
func (p *Plugin) validateIDTokenHint(ctx context.Context, idTokenHint string) (subject, clientID string, err error) {
	if p.keyStore == nil {
		return "", "", nil
	}

	verifier := protocol.NewIDTokenHintVerifier(
		shared.IssuerFromContext(ctx),
		nil,
	)
	verifier.KeyStore = p.keyStore

	claims, err := protocol.VerifyIDTokenHint(ctx, idTokenHint, verifier)
	if err != nil {
		// Expired ID token hints are acceptable per OIDC spec.
		var expiredErr protocol.IDTokenHintExpiredError
		if errors.As(err, &expiredErr) && claims != nil {
			// Token is expired but claims are still valid for hint purposes.
		} else {
			return "", "", err
		}
	}

	subject = claims.Subject
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	return subject, clientID, nil
}
