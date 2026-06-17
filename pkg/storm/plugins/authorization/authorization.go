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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jws"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// defaultIDTokenLifetime is the default lifetime for ID tokens issued
// in the Implicit Flow. Can be overridden per-client via IDTokenLifetimeProvider.
const defaultIDTokenLifetime = 1 * time.Hour

// Plugin implements the OIDC Authorization endpoint.
type Plugin struct {
	authStore                 storm.AuthStore
	clientStore               storm.ClientStore
	crypto                    storm.UniCrypto
	keyStore                  storm.KeyStore
	tokenStore                storm.TokenStore
	decoder                   *protocol.Decoder
	enableImplicit            bool
	allowPlainPKCE            bool
	allowPrivateIPs           bool
	skipTLSCertVerify         bool
	parStore                  storm.PARStore
	sessionProvider           SessionProvider
	jarmSigner                JARMSigner // optional, set via SetJARMSigner
	tracer                    trace.Tracer
	createAuthCode            func(ctx context.Context, authReq storm.AuthRequest, store storm.AuthStore, enc storm.UniCrypto) (string, error)
	authorizationDetailsTypes []string                    // RFC 9396 supported types
	sessionRecorder           storm.ClientSessionRecorder // optional, for back-channel logout tracking
}

//go:embed template/form_post.html.tmpl
var formPostHtmlTemplate string

var formPostTmpl = template.Must(template.New("form_post").Parse(formPostHtmlTemplate))

// SessionProvider is an optional interface for checking whether an
// end-user session exists. When the client storage implements this,
// the Authorization plugin uses it to enforce prompt=none (OIDC Core
// §3.1.2.6): if no session exists the endpoint returns login_required
// immediately instead of redirecting to the login UI.
//
// When a session exists, GetSession returns the subject and the
// original authentication time (auth_time). The auth_time is used
// to populate the auth_time claim in ID tokens, ensuring consistency
// across multiple token issuances for the same session.
type SessionProvider interface {
	GetSession(ctx context.Context, r *http.Request, clientID string) (subject string, authTime time.Time, sid string, ok bool)
}

// Config holds the dependencies for the Authorization plugin.
type Config struct {
	AuthStore   storm.AuthStore
	ClientStore storm.ClientStore
	Crypto      storm.UniCrypto
	KeyStore    storm.KeyStore
	TokenStore  storm.TokenStore
	Decoder     *protocol.Decoder

	// EnableImplicit enables the Implicit Flow (response_type=id_token,
	// id_token token). Disabled by default per OAuth 2.1.
	EnableImplicit bool

	// AllowPlainPKCE enables the "plain" code_challenge_method (RFC 7636).
	// Disabled by default per OAuth 2.1 §4.1.1. Clients must explicitly
	// opt-in by setting this to true. When false, only S256 is accepted.
	AllowPlainPKCE bool

	// PARStore enables Pushed Authorization Requests (RFC 9101).
	// When set, request_uri references are resolved from this store.
	PARStore storm.PARStore

	// CreateAuthCode is an optional hook to customize authorization code
	// generation (Tenant-level). When nil, the default implementation
	// encrypts the auth request ID using the configured Crypto.
	CreateAuthCode func(ctx context.Context, authReq storm.AuthRequest, store storm.AuthStore, enc storm.UniCrypto) (string, error)

	// SessionProvider is an optional session checker for prompt=none
	// enforcement. When nil, prompt=none is not enforced at the
	// authorization endpoint (the login UI is always shown).
	SessionProvider SessionProvider

	// AuthorizationDetailsTypes lists the authorization_details type values
	// this OP supports. When non-empty, the discovery document includes
	// authorization_details_types_supported (RFC 9396 §6).
	// Example: []string{"payment_initiation", "account_information"}
	AuthorizationDetailsTypes []string
}

// New creates a new Authorization plugin from a PluginContext.
// Storage must implement AuthStore, ClientStore, and KeyStore.
// If Storage also implements TokenStore, it is used for Implicit Flow
// access token generation. If Storage implements PARStore, Pushed
// Authorization Requests are enabled.
func New(ctx *storm.PluginContext) *Plugin {
	p := &Plugin{
		authStore:         ctx.Storage.(storm.AuthStore),
		clientStore:       ctx.Storage.(storm.ClientStore),
		crypto:            ctx.Crypto,
		keyStore:          ctx.Storage.(storm.KeyStore),
		decoder:           ctx.Decoder,
		enableImplicit:    ctx.EnableImplicit,
		allowPlainPKCE:    ctx.AllowPlainPKCE,
		allowPrivateIPs:   ctx.AllowPrivateIPs,
		skipTLSCertVerify: ctx.SkipTLSCertVerify,
		tracer:            ctx.Tracer,
	}
	// Register custom parser for OIDC §5.5 claims parameter (JSON object).
	ctx.Decoder.RegisterParser(
		reflect.TypeOf(&protocol.ClaimsRequest{}),
		func(s string) (reflect.Value, error) {
			if s == "" {
				return reflect.Zero(reflect.TypeOf(&protocol.ClaimsRequest{})), nil
			}
			cr := new(protocol.ClaimsRequest)
			if err := json.Unmarshal([]byte(s), cr); err != nil {
				return reflect.Value{}, fmt.Errorf("invalid claims parameter: %w", err)
			}
			return reflect.ValueOf(cr), nil
		},
	)
	// Optionally extract TokenStore and PARStore from storage.
	if ts, ok := ctx.Storage.(storm.TokenStore); ok {
		p.tokenStore = ts
	}
	if ps, ok := ctx.Storage.(storm.PARStore); ok {
		p.parStore = ps
	}
	if sp, ok := ctx.Storage.(SessionProvider); ok {
		p.sessionProvider = sp
	}
	if sr, ok := ctx.Storage.(storm.ClientSessionRecorder); ok {
		p.sessionRecorder = sr
	}
	return p
}

// NewWithConfig creates a new Authorization plugin with explicit config.
// Use this when you need to override defaults (e.g., enable implicit flow).
func NewWithConfig(cfg Config) *Plugin {
	return &Plugin{
		authStore:                 cfg.AuthStore,
		clientStore:               cfg.ClientStore,
		crypto:                    cfg.Crypto,
		keyStore:                  cfg.KeyStore,
		tokenStore:                cfg.TokenStore,
		decoder:                   cfg.Decoder,
		enableImplicit:            cfg.EnableImplicit,
		allowPlainPKCE:            cfg.AllowPlainPKCE,
		parStore:                  cfg.PARStore,
		sessionProvider:           cfg.SessionProvider,
		createAuthCode:            cfg.CreateAuthCode,
		authorizationDetailsTypes: cfg.AuthorizationDetailsTypes,
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

// SetJARMSigner sets the JARM signer for JWT-secured authorization responses.
// Called by the Engine during Build when both authorization and jarm plugins are present.
func (p *Plugin) SetJARMSigner(signer JARMSigner) {
	p.jarmSigner = signer
}

// recordSession records the client session for back-channel logout tracking.
// Only records when the storage implements ClientSessionRecorder and the
// auth request provides a SID.
func (p *Plugin) recordSession(ctx context.Context, authReq storm.AuthRequest) {
	if p.sessionRecorder == nil {
		return
	}
	if sid := authReq.GetSID(); sid != "" {
		p.sessionRecorder.RecordClientSession(authReq.GetSubject(), authReq.GetClientID(), sid)
	}
}

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

// Contribute populates the discovery fields for the authorization endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.AuthorizationEndpoint = shared.EndpointURL(ctx, protocol.NewEndpoint("/authorize"))

	// Authorization endpoint capabilities
	cfg.ScopesSupported = append(cfg.ScopesSupported,
		"openid", "profile", "email", "address", "phone", "offline_access",
	)
	cfg.ResponseTypesSupported = append(cfg.ResponseTypesSupported, "code")
	cfg.ResponseModesSupported = append(cfg.ResponseModesSupported,
		"query", "fragment", "form_post",
	)
	cfg.GrantTypesSupported = append(cfg.GrantTypesSupported, "authorization_code")
	cfg.CodeChallengeMethodsSupported = append(cfg.CodeChallengeMethodsSupported, "S256")
	if p.allowPlainPKCE {
		cfg.CodeChallengeMethodsSupported = append(cfg.CodeChallengeMethodsSupported, "plain")
	}

	// Implicit/hybrid response types (only when enabled)
	if p.enableImplicit {
		cfg.ResponseTypesSupported = append(cfg.ResponseTypesSupported,
			"id_token", "id_token token",
			"code id_token", "code token", "code id_token token",
		)
	}

	// RFC 9207: iss parameter in authorization response
	cfg.AuthorizationResponseISSParameterSupported = true

	// RFC 8707: Resource Indicators for OAuth 2.0
	cfg.ResourceIndicatorsSupported = true

	// RFC 9396: Rich Authorization Requests
	if len(p.authorizationDetailsTypes) > 0 {
		cfg.AuthorizationDetailsTypesSupported = p.authorizationDetailsTypes
	}
}

// --- authorize handler ---

func (p *Plugin) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// DEBUG: log every request hitting the authorize endpoint
	slog.Info("handleAuthorize: REQUEST RECEIVED",
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)
	ctx, span := shared.TracerSpan(r.Context(), p.tracer, "authorization.authorize")
	defer span.End()
	if p.jarmSigner != nil {
		ctx = contextWithJARMSigner(ctx, p.jarmSigner)
	}
	r = r.WithContext(ctx)

	if err := r.ParseForm(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cannot parse form")
		writeAuthError(w, r, "", "", "", protocol.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err))
		return
	}

	authReq, err := parseAuthorizeRequest(r.Form, p.decoder)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cannot parse auth request")
		writeAuthError(w, r, "", "", "", protocol.ErrInvalidRequest().WithDescription("cannot parse auth request").WithParent(err))
		return
	}

	span.SetAttributes(
		attribute.String("client_id", authReq.ClientID),
		attribute.String("response_type", string(authReq.ResponseType)),
		attribute.String("redirect_uri", authReq.RedirectURI),
		attribute.StringSlice("scopes", []string(authReq.Scopes)),
	)

	// DEBUG: trace scope after initial form parsing
	slog.Info("authorize: after parseAuthorizeRequest",
		slog.Any("scopes", authReq.Scopes),
		slog.String("client_id", authReq.ClientID),
		slog.String("request_param_present", fmt.Sprintf("%v", authReq.RequestParam != "")),
		slog.String("request_uri", authReq.RequestURI),
	)

	// Resolve effective response mode: explicit > implicit default from response_type.
	// Per OAuth 2.0 Multiple Response Types §2.1, hybrid/implicit flows default to fragment.
	// NOTE: This is calculated AFTER request_uri/PAR resolution so that response_mode
	// from the request object or PAR request is properly reflected.
	// (initial calculation removed — moved below request_uri/PAR resolution)

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
		slog.Info("authorize: after applyRequestObject",
			slog.Any("scopes", authReq.Scopes),
			slog.String("client_id", authReq.ClientID),
		)
	}

	// Resolve request_uri (OIDC Core §6.1, RFC 9101 §5.2)
	if authReq.RequestURI != "" {
		if strings.HasPrefix(authReq.RequestURI, "http://") || strings.HasPrefix(authReq.RequestURI, "https://") {
			// request_uri is a URL pointing to a signed JWT request object (OIDC Core §6.1)
			if err := p.applyRequestURI(r.Context(), authReq); err != nil {
				shared.WriteError(w, r, err, nil)
				return
			}
			slog.Info("authorize: after applyRequestURI",
				slog.Any("scopes", authReq.Scopes),
				slog.String("client_id", authReq.ClientID),
			)
		} else {
			// request_uri is a PAR reference (RFC 9101 §5.2)
			if p.parStore == nil {
				shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("request_uri not supported"), nil)
				return
			}
			if err := p.applyPARRequest(r.Context(), authReq); err != nil {
				shared.WriteError(w, r, err, nil)
				return
			}
			slog.Info("authorize: after applyPARRequest",
				slog.Any("scopes", authReq.Scopes),
				slog.String("client_id", authReq.ClientID),
				slog.String("redirect_uri", authReq.RedirectURI),
			)
		}
	}

	// Resolve effective response mode AFTER request_uri/PAR resolution.
	resolvedMode := resolveResponseMode(authReq.ResponseMode, authReq.ResponseType)
	slog.Info("authorize: resolved response mode",
		slog.String("authReq_response_mode", string(authReq.ResponseMode)),
		slog.String("authReq_response_type", string(authReq.ResponseType)),
		slog.String("resolved_mode", string(resolvedMode)),
		slog.String("client_id", authReq.ClientID),
	)

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
	// Store clientID in context for JARM error responses.
	if authReq.ClientID != "" {
		r = r.WithContext(contextWithJARMClientID(r.Context(), authReq.ClientID))
	}
	// Store client's preferred signing algorithm for JARM signing.
	if algProvider, ok := client.(shared.IDTokenSignedResponseAlgProvider); ok {
		if alg := algProvider.IDTokenSignedResponseAlg(); alg != "" {
			r = r.WithContext(shared.ContextWithJARMPreferredAlg(r.Context(), alg))
		}
	}

	// Validate redirect_uri first — separately from other params.
	// Per OIDC Core §3.1.2.4: if redirect_uri is not registered, the OP
	// MUST NOT redirect to it and MUST display an error directly.
	redirectURIErr := validateRedirectURI(client, authReq.RedirectURI, authReq.ResponseType)
	if redirectURIErr != nil {
		shared.WriteError(w, r, redirectURIErr, nil)
		return
	}

	// RFC 9449 §7.1: if the authorization request includes a DPoP proof
	// header and dpop_jkt was not already set (e.g. from PAR data or
	// request object), capture the JWK thumbprint for code binding.
	if authReq.DPoPJKT == "" {
		if dpopProof := shared.DPoPFromContext(r.Context()); dpopProof != nil {
			authReq.DPoPJKT = dpopProof.JWKThumbprint()
			slog.Info("authorize: captured DPoP JKT from proof",
				slog.String("jkt", authReq.DPoPJKT),
			)
		}
	}

	// FAPI 2.0 §5.3.1: the authorization server SHALL require the use of
	// PAR or a request object. Reject plain query-string requests for
	// FAPI 2.0 clients.
	if fapiClient, ok := client.(interface{ FAPIProfile() bool }); ok && fapiClient.FAPIProfile() {
		if authReq.RequestURI == "" && authReq.RequestParam == "" {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.ErrInvalidRequest().WithDescription("FAPI 2.0 requires a request object or PAR (request_uri)"))
			return
		}
	}

	// FAPI 2.0 signed_non_repudiation: if the client is configured with a
	// request_object_signing_alg, a signed request object is required.
	// For PAR-based requests the request object was already validated at the
	// PAR endpoint, so we only enforce this on direct authorization requests.
	if authReq.RequestURI == "" {
		if err := shared.ValidateSignedRequestObjectRequired(client, authReq.RequestParam != ""); err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode, err)
			return
		}
	}

	// Now that redirect_uri is validated, remaining errors can be
	// safely redirected to the registered URI.
	slog.Info("authorize: before validateAuthRequestParamsExceptRedirectURI",
		slog.Any("scopes", authReq.Scopes),
		slog.Int("scopes_len", len(authReq.Scopes)),
	)
	if err := validateAuthRequestParamsExceptRedirectURI(client, authReq); err != nil {
		slog.Error("authorize: validation failed",
			slog.Any("error", err),
			slog.Any("scopes", authReq.Scopes),
		)
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode, err)
		return
	}
	slog.Info("authorize: after validateAuthRequestParamsExceptRedirectURI",
		slog.Any("scopes", authReq.Scopes),
		slog.Int("scopes_len", len(authReq.Scopes)),
	)

	// Reject plain PKCE unless explicitly allowed (OAuth 2.1 §4.1.1).
	// S256 is always accepted; plain requires the server to opt in.
	if !p.allowPlainPKCE && authReq.CodeChallengeMethod == protocol.CodeChallengeMethodPlain {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
			protocol.ErrInvalidRequest().WithDescription("plain code_challenge_method is not allowed; use S256"))
		return
	}

	// Validate id_token_hint (OIDC Core §3.1.2.2)
	var idTokenHintSubject string
	if authReq.IDTokenHint != "" {
		subject, _, err := p.validateIDTokenHint(r.Context(), authReq.IDTokenHint)
		if err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.ErrInvalidRequest().WithDescription("invalid id_token_hint").WithParent(err))
			return
		}
		idTokenHintSubject = subject
		// Note: subject matching is delegated to the login UI, which can
		// re-parse the id_token_hint to extract the sub claim and compare
		// it against the authenticated user. Per OIDC Core §3.1.2.2, if
		// the identified user does not match, the OP SHOULD return an error.
	}

	// Implicit/hybrid flow guard: disabled by default per OAuth 2.1
	if !p.enableImplicit && (isImplicitResponseType(authReq.ResponseType) || isHybridResponseType(authReq.ResponseType)) {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
			protocol.ErrInvalidRequest().WithDescription("implicit/hybrid flow is disabled"))
		return
	}

	// Invoke AuthorizeValidator extension point if client implements it.
	if avc, ok := client.(AuthorizeValidatorClient); ok {
		if err := avc.AuthorizeValidator().ValidateAuthRequest(client, authReq); err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode, err)
			return
		}
	}

	// OIDC Core §3.1.2.6: prompt=none MUST NOT display any UI.
	// If no session exists, return login_required immediately.
	// If a session exists, auto-complete the auth request with the
	// original auth_time and skip the login UI entirely.
	//
	// Session resolution order:
	//   1. session cookie (browser clients)
	//   2. id_token_hint subject lookup (API / conformance-test clients)
	//   3. login_hint subject lookup
	//
	// If both cookie and id_token_hint are present, the subjects MUST match;
	// otherwise the request is treated as unauthenticated per OIDC Core §3.1.2.2.
	if slices.Contains(authReq.Prompt, protocol.PromptNone) {
		if p.sessionProvider == nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.ErrLoginRequired().WithDescription("prompt=none but no session provider configured"))
			return
		}

		cookieSubject, cookieAuthTime, cookieSID, cookieOK := p.sessionProvider.GetSession(r.Context(), r, authReq.ClientID)

		// Resolve subject from hints when cookie is absent or to cross-check.
		var hintSubject string
		if idTokenHintSubject != "" {
			hintSubject = idTokenHintSubject
		} else if authReq.LoginHint != "" {
			hintSubject = authReq.LoginHint
		}

		var subject string
		var authTime time.Time
		var sid string
		var ok bool

		switch {
		case cookieOK && hintSubject != "":
			// Both cookie and hint present — subjects must match.
			if cookieSubject == hintSubject {
				subject, authTime, sid, ok = cookieSubject, cookieAuthTime, cookieSID, true
			} else {
				writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
					protocol.ErrLoginRequired().WithDescription("session subject does not match id_token_hint"))
				return
			}
		case cookieOK:
			subject, authTime, sid, ok = cookieSubject, cookieAuthTime, cookieSID, true
		case hintSubject != "":
			if sessionBySubject, canLookup := p.sessionProvider.(interface {
				GetSessionBySubject(subject string) (authTime time.Time, sid string, ok bool)
			}); canLookup {
				authTime, sid, ok = sessionBySubject.GetSessionBySubject(hintSubject)
				if ok {
					subject = hintSubject
				}
			}
		}

		if !ok {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.ErrLoginRequired().WithDescription("user is not logged in"))
			return
		}

		// Auto-complete: create auth request with subject, mark done
		// with the original auth_time, then directly produce the auth
		// response — no login UI redirect.
		completer, ok := p.authStore.(storm.AutoCompleteAuthRequest)
		if !ok {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.ErrServerError().WithDescription("prompt=none requires AutoCompleteAuthRequest support"))
			return
		}
		req, err := p.authStore.CreateAuthRequest(r.Context(), authReq, subject)
		if err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.DefaultToServerError(err, "unable to save auth request"))
			return
		}
		// Store DPoP code binding if present (RFC 9449 §7.1)
		p.storeDPoPCodeBinding(r.Context(), req.GetID(), authReq.DPoPJKT)
		if err := completer.CompleteAuthRequest(r.Context(), req.GetID(), subject, authTime, sid); err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.DefaultToServerError(err, "unable to complete auth request"))
			return
		}
		completed, err := p.authStore.AuthRequestByID(r.Context(), req.GetID())
		if err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.DefaultToServerError(err, "unable to fetch completed auth request"))
			return
		}
		p.authResponse(w, r, completed)
		return
	}

	// OIDC Core §3.1.2.1: max_age specifies the allowable elapsed
	// time since the last authentication. If the session auth_time
	// is within the max_age window, skip re-authentication and
	// auto-complete with the original auth_time.
	if authReq.MaxAge != nil && p.sessionProvider != nil {
		subject, authTime, sid, ok := p.sessionProvider.GetSession(r.Context(), r, authReq.ClientID)
		if ok {
			elapsed := time.Since(authTime)
			if elapsed <= time.Duration(*authReq.MaxAge)*time.Second {
				completer, ok := p.authStore.(storm.AutoCompleteAuthRequest)
				if !ok {
					writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
						protocol.ErrServerError().WithDescription("max_age auto-complete requires AutoCompleteAuthRequest support"))
					return
				}
				req, err := p.authStore.CreateAuthRequest(r.Context(), authReq, subject)
				if err != nil {
					writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
						protocol.DefaultToServerError(err, "unable to save auth request"))
					return
				}
				// Store DPoP code binding if present (RFC 9449 §7.1)
				p.storeDPoPCodeBinding(r.Context(), req.GetID(), authReq.DPoPJKT)
				if err := completer.CompleteAuthRequest(r.Context(), req.GetID(), subject, authTime, sid); err != nil {
					writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
						protocol.DefaultToServerError(err, "unable to complete auth request"))
					return
				}
				completed, err := p.authStore.AuthRequestByID(r.Context(), req.GetID())
				if err != nil {
					writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
						protocol.DefaultToServerError(err, "unable to fetch completed auth request"))
					return
				}
				p.authResponse(w, r, completed)
				return
			}
			// max_age exceeded — fall through to login UI for re-authentication
		}
		// No session — fall through to login UI
	}

	req, err := p.authStore.CreateAuthRequest(r.Context(), authReq, "")
	if err != nil {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
			protocol.DefaultToServerError(err, "unable to save auth request"))
		return
	}
	// Store DPoP code binding if present (RFC 9449 §7.1)
	p.storeDPoPCodeBinding(r.Context(), req.GetID(), authReq.DPoPJKT)

	loginURL := client.LoginURL(req.GetID())
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// storeDPoPCodeBinding stores the DPoP JWK thumbprint for code binding (RFC 9449 §7.1).
func (p *Plugin) storeDPoPCodeBinding(ctx context.Context, authRequestID string, jkt string) {
	if jkt == "" {
		return
	}
	if bindingStore, ok := p.authStore.(storm.DPoPCodeBindingStore); ok {
		bindingStore.SetAuthRequestDPoPJKT(ctx, authRequestID, jkt)
	}
}

// --- callback handler ---

func (p *Plugin) handleCallback(w http.ResponseWriter, r *http.Request) {
	if p.jarmSigner != nil {
		r = r.WithContext(contextWithJARMSigner(r.Context(), p.jarmSigner))
	}
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
	// Store clientID in context for JARM error responses.
	if authReq.GetClientID() != "" {
		r = r.WithContext(contextWithJARMClientID(r.Context(), authReq.GetClientID()))
	}
	// Store client's preferred signing algorithm for JARM signing.
	if jarmClient, err := p.clientStore.GetClientByClientID(r.Context(), authReq.GetClientID()); err == nil {
		if algProvider, ok := jarmClient.(shared.IDTokenSignedResponseAlgProvider); ok {
			if alg := algProvider.IDTokenSignedResponseAlg(); alg != "" {
				r = r.WithContext(shared.ContextWithJARMPreferredAlg(r.Context(), alg))
			}
		}
	}

	// If the login UI passed an error (e.g. user cancelled), return it
	// via the authorization error response (JARM-aware).
	if errorParam := r.Form.Get("error"); errorParam != "" {
		description := r.Form.Get("error_description")
		if description == "" {
			description = errorParam
		}
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType()),
			protocol.ToOAuthError(errorParam).WithDescription("%s", description))
		return
	}

	if !authReq.Done() {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType()),
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

	if p.enableImplicit && isHybridResponseType(authReq.GetResponseType()) {
		p.authResponseHybrid(w, r, authReq)
		return
	}

	writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
		resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType()),
		protocol.ErrServerError().WithDescription("unsupported response_type"))
}

// authResponseCode handles the authorization code response.
func (p *Plugin) authResponseCode(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	createCode := createAuthRequestCode
	if p.createAuthCode != nil {
		createCode = p.createAuthCode
	}
	code, err := createCode(r.Context(), authReq, p.authStore, p.crypto)
	if err != nil {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType()),
			protocol.DefaultToServerError(err, "failed to create auth code"))
		return
	}

	redirectURI := authReq.GetRedirectURI()
	responseMode := resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType())

	// Build response payload.
	resp := &codeResponse{
		Code:   code,
		State:  authReq.GetState(),
		Issuer: shared.IssuerFromContext(r.Context()), // RFC 9207
	}

	// Include session_state if client supports it.
	if ssc, ok := authReq.(SessionStateClient); ok {
		resp.SessionState = ssc.GetSessionState()
	}

	// JARM response modes (RFC 9101)
	slog.Info("authorize: checking JARM",
		slog.String("response_mode", string(responseMode)),
		slog.Bool("is_jarm", isJARMResponseMode(responseMode)),
		slog.Bool("has_signer", p.jarmSigner != nil),
	)
	if isJARMResponseMode(responseMode) && p.jarmSigner != nil {
		// Resolve "jwt" shorthand to concrete JARM mode (RFC 9101 §4.1).
		effectiveRM := responseMode
		if responseMode == protocol.ResponseModeJWT {
			if usesFragmentDefault(authReq.GetResponseType()) {
				effectiveRM = protocol.ResponseModeFragmentJWT
			} else {
				effectiveRM = protocol.ResponseModeQueryJWT
			}
		}
		params := map[string]string{
			"code": resp.Code,
		}
		if resp.State != "" {
			params["state"] = resp.State
		}
		if resp.SessionState != "" {
			params["session_state"] = resp.SessionState
		}
		// RFC 9207: iss parameter (JARM JWT already contains iss via issuer claim,
		// but we include it explicitly for consistency)
		if resp.Issuer != "" {
			params["iss"] = resp.Issuer
		}

		slog.Info("authorize: calling SignAuthResponse",
			slog.String("clientID", authReq.GetClientID()),
			slog.Any("params", params),
		)
		jwt, err := p.jarmSigner.SignAuthResponse(r.Context(), params, authReq.GetClientID(), shared.JARMPreferredAlgFromContext(r.Context()))
		if err != nil {
			slog.Error("authorize: JARM signing failed", slog.Any("error", err))
			writeAuthError(w, r, redirectURI, authReq.GetState(), responseMode,
				protocol.DefaultToServerError(err, "failed to sign JARM response"))
			return
		}

		slog.Info("authorize: JARM signed",
			slog.String("effectiveRM", string(effectiveRM)),
			slog.String("redirectURI", redirectURI),
			slog.String("jwt_prefix", truncateStr(jwt, 80)),
		)

		writeJARMResponse(w, r, redirectURI, jwt, effectiveRM)
		return
	}

	// Form Post response mode (OIDC Core §3.1.2.5 / §3.3.2.5)
	if responseMode == protocol.ResponseModeFormPost {
		if err := writeFormPostResponse(w, redirectURI, resp); err != nil {
			writeAuthError(w, r, redirectURI, authReq.GetState(), responseMode, err)
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
	// RFC 9207: iss parameter in authorization response
	if resp.Issuer != "" {
		params.Set("iss", resp.Issuer)
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
		queries := u.Query()
		for key, vals := range params {
			for _, val := range vals {
				queries.Add(key, val)
			}
		}
		u.RawQuery = queries.Encode()
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
	// RFC 9207: iss parameter in authorization response
	if response.Issuer != "" {
		values["iss"] = []string{response.Issuer}
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

// parseAuthorizeRequest, validateAuthRequestParamsExceptRedirectURI, validateRedirectURI,
// validateRedirectURIWeb, validateRedirectURINative, checkRedirectURIAgainstClient,
// validatePrompt, validateScopes, validateResponseType, createAuthRequestCode,
// validatePKCE, validateNonce, writeFormPostError,
// isImplicitResponseType, copyRequestObjectToAuthRequest, and algorithmToJWA
// are defined in util.go.

// --- implicit flow ---

// authResponseImplicit handles the Implicit Flow response.
//
// Per OIDC Core 1.0 §3.2.2.5 (Successful Authentication Response):
//   - response_type=id_token: returns only id_token in the fragment
//   - response_type=id_token token: returns access_token, token_type, and id_token in the fragment
//
// All response parameters are added to the redirect URI's fragment component,
// per OAuth 2.0 Multiple Response Types Encoding Practice §2.1.
//
// Important: When access_token is returned, the id_token MUST contain the
// at_hash claim (OIDC Core §3.2.2.1). Therefore, we create the access_token
// FIRST and pass it to createImplicitIDToken so it can compute at_hash.
func (p *Plugin) authResponseImplicit(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	if _, err := url.Parse(authReq.GetRedirectURI()); err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithParent(err), nil)
		return
	}

	fragment := url.Values{}
	fragment.Set("state", authReq.GetState())

	// RFC 9207: iss parameter in authorization response
	if iss := shared.IssuerFromContext(r.Context()); iss != "" {
		fragment.Set("iss", iss)
	}

	// Per OIDC Core §3.2.2.5: access_token is returned when response_type is "id_token token"
	// We create it first so we can pass it to createImplicitIDToken for at_hash computation.
	var accessToken string
	if authReq.GetResponseType() == protocol.ResponseTypeIDToken {
		token, expiresIn, err := p.createImplicitAccessToken(r.Context(), authReq)
		if err == nil && token != "" {
			accessToken = token
			fragment.Set("access_token", accessToken)
			fragment.Set("token_type", protocol.BearerToken)
			if expiresIn > 0 {
				fragment.Set("expires_in", fmt.Sprintf("%d", expiresIn))
			}
		}
	}

	// Per OIDC Core §3.2.2.5: id_token is REQUIRED for both response types
	// When access_token is present, id_token MUST include at_hash (§3.2.2.1)
	if authReq.GetResponseType() == protocol.ResponseTypeIDTokenOnly ||
		authReq.GetResponseType() == protocol.ResponseTypeIDToken {
		// Resolve client for IDTokenLifetimeProvider extension.
		var client storm.Client
		if c, err := p.clientStore.GetClientByClientID(r.Context(), authReq.GetClientID()); err == nil {
			client = c
		}
		idToken, err := p.createImplicitIDToken(r.Context(), authReq, accessToken, "", client)
		if err == nil && idToken != "" {
			fragment.Set("id_token", idToken)
		}
	}

	// Record client session for back-channel logout tracking.
	p.recordSession(r.Context(), authReq)

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

	tokenID, expiration, err := p.tokenStore.CreateAccessToken(ctx, authReq, nil)
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
	return base64.RawURLEncoding.EncodeToString(encrypted), expiresIn, nil
}

// createImplicitIDToken creates a signed ID token for the Implicit Flow.
//
// Per OIDC Core 1.0 §3.2.2.5 (Successful Authentication Response):
//   - The ID Token is REQUIRED for all Implicit Flow responses
//   - When access_token is also returned (response_type=id_token token),
//     the ID Token MUST contain the at_hash claim (§3.2.2.1)
//
// The at_hash value is the base64url encoding of the left-most half of the
// hash of the octets of the ASCII representation of the access_token value,
// where the hash algorithm used is the hash algorithm used in the alg Header
// Parameter of the ID Token's JOSE Header (OIDC Core §2).
func (p *Plugin) createImplicitIDToken(ctx context.Context, authReq storm.AuthRequest, accessToken, code string, client storm.Client) (string, error) {
	if p.keyStore == nil {
		return "", nil
	}
	signingKey, err := p.keyStore.SigningKey(ctx)
	if err != nil {
		return "", err
	}

	// If the client specifies a preferred ID token signing algorithm, try to
	// use a matching signing key (OIDC Core §2: id_token_signed_response_alg).
	if client != nil {
		if algProvider, ok := client.(shared.IDTokenSignedResponseAlgProvider); ok {
			if alg := algProvider.IDTokenSignedResponseAlg(); alg != "" {
				if algStore, ok := p.keyStore.(storm.SigningKeyByAlgProvider); ok {
					if algKey, err := algStore.SigningKeyByAlg(ctx, alg); err == nil {
						signingKey = algKey
					}
				}
			}
		}
	}

	// Determine ID token lifetime: per-client override or default (1 hour).
	lifetime := defaultIDTokenLifetime
	if client != nil {
		if lp, ok := client.(IDTokenLifetimeProvider); ok {
			lifetime = lp.IDTokenLifetime()
		}
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss": shared.IssuerFromContext(ctx),
		"sub": authReq.GetSubject(),
		"aud": authReq.GetClientID(),
		"iat": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
	}
	// OIDC Core §3.2.2.1: nonce is REQUIRED for Implicit Flow
	if nonce := authReq.GetNonce(); nonce != "" {
		claims["nonce"] = nonce
	}
	// OIDC Core §2 / §15.1: auth_time is REQUIRED when max_age is requested
	// or when the client requires it via claims parameter.
	if t := authReq.GetAuthTime(); !t.IsZero() {
		claims["auth_time"] = t.Unix()
	}
	if acr := authReq.GetACR(); acr != "" {
		claims["acr"] = acr
	}
	if amr := authReq.GetAMR(); len(amr) > 0 {
		claims["amr"] = amr
	}
	if sid := authReq.GetSID(); sid != "" {
		claims["sid"] = sid
	}
	// OIDC Core §2 / §3.2.2.1: at_hash is REQUIRED when access_token is returned
	// "Access Token hash value. Its value is the base64url encoding of the left-most
	// half of the hash of the octets of the ASCII representation of the access_token value"
	if accessToken != "" {
		claims["at_hash"] = hashTokenForIDToken(accessToken, signingKey.Algorithm(), p.crypto)
	}
	// OIDC Core §3.3.2.11: c_hash is REQUIRED when code is returned in hybrid flow
	if code != "" {
		claims["c_hash"] = hashTokenForIDToken(code, signingKey.Algorithm(), p.crypto)
	}

	// Merge extra claims from auth request (e.g. acr, amr).
	// Standard claims set above take precedence and cannot be overridden.
	if ext, ok := authReq.(IDTokenClaimsExtender); ok {
		for k, v := range ext.ExtraIDTokenClaims() {
			if _, exists := claims[k]; !exists {
				claims[k] = v
			}
		}
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

// --- hybrid flow ---

// authResponseHybrid handles the Hybrid Flow response (OIDC Core §3.3).
//
// Hybrid flow returns both an authorization code and tokens in the fragment:
//   - response_type=code id_token: code + id_token
//   - response_type=code token: code + access_token
//   - response_type=code id_token token: code + access_token + id_token
//
// All parameters are returned in the fragment per OAuth 2.0 Multiple Response Types §2.1.
func (p *Plugin) authResponseHybrid(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	if _, err := url.Parse(authReq.GetRedirectURI()); err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithParent(err), nil)
		return
	}

	fragment := url.Values{}
	fragment.Set("state", authReq.GetState())

	// RFC 9207: iss parameter in authorization response
	if iss := shared.IssuerFromContext(r.Context()); iss != "" {
		fragment.Set("iss", iss)
	}

	// Create authorization code (always present in hybrid flows).
	createCode := createAuthRequestCode
	if p.createAuthCode != nil {
		createCode = p.createAuthCode
	}
	code, err := createCode(r.Context(), authReq, p.authStore, p.crypto)
	if err != nil {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType()),
			protocol.DefaultToServerError(err, "failed to create auth code"))
		return
	}
	fragment.Set("code", code)

	// Create access_token if response_type includes "token".
	var accessToken string
	rt := authReq.GetResponseType()
	if rt == protocol.ResponseTypeCodeToken || rt == protocol.ResponseTypeCodeIDTokenToken {
		token, expiresIn, err := p.createImplicitAccessToken(r.Context(), authReq)
		if err == nil && token != "" {
			accessToken = token
			fragment.Set("access_token", accessToken)
			fragment.Set("token_type", protocol.BearerToken)
			if expiresIn > 0 {
				fragment.Set("expires_in", fmt.Sprintf("%d", expiresIn))
			}
		}
	}

	// Create id_token if response_type includes "id_token".
	if rt == protocol.ResponseTypeCodeIDToken || rt == protocol.ResponseTypeCodeIDTokenToken {
		var client storm.Client
		if c, err := p.clientStore.GetClientByClientID(r.Context(), authReq.GetClientID()); err == nil {
			client = c
		}
		idToken, err := p.createImplicitIDToken(r.Context(), authReq, accessToken, code, client)
		if err == nil && idToken != "" {
			fragment.Set("id_token", idToken)
		}
	}

	// Record client session for back-channel logout tracking.
	p.recordSession(r.Context(), authReq)

	// Build fragment URL.
	redirectURL := authReq.GetRedirectURI()
	if idx := strings.Index(redirectURL, "#"); idx >= 0 {
		redirectURL = redirectURL[:idx]
	}
	redirectURL += "#" + fragment.Encode()

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// --- request object / PAR helpers ---

// applyRequestObject parses and validates a JWT request object (OIDC Core §6.1).
func (p *Plugin) applyRequestObject(ctx context.Context, authReq *protocol.AuthRequest) error {
	lookupClient := func(ctx context.Context, clientID string) (shared.Client, error) {
		return p.clientStore.GetClientByClientID(ctx, clientID)
	}
	return shared.ParseAndValidateRequestObject(ctx, authReq, lookupClient)
}

// applyRequestURI fetches and validates a signed JWT request object from a URL (OIDC Core §6.1).
func (p *Plugin) applyRequestURI(ctx context.Context, authReq *protocol.AuthRequest) error {
	// Fetch the JWT from the URL
	client := shared.NewHTTPClient(p.skipTLSCertVerify)
	resp, err := client.Get(authReq.RequestURI)
	if err != nil {
		return protocol.ErrInvalidRequestObject().WithDescription("failed to fetch request_uri: %s", authReq.RequestURI).WithParent(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.ErrInvalidRequestObject().WithDescription("request_uri returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return protocol.ErrInvalidRequestObject().WithDescription("failed to read request_uri response").WithParent(err)
	}

	// Set the fetched JWT as the request parameter and validate using shared logic.
	authReq.RequestParam = strings.TrimSpace(string(body))
	lookupClient := func(ctx context.Context, clientID string) (shared.Client, error) {
		return p.clientStore.GetClientByClientID(ctx, clientID)
	}
	return shared.ParseAndValidateRequestObject(ctx, authReq, lookupClient)
}

// applyPARRequest resolves a Pushed Authorization Request (RFC 9101 §5.2).
func (p *Plugin) applyPARRequest(ctx context.Context, authReq *protocol.AuthRequest) error {
	parReq, err := p.parStore.GetPushedAuthRequest(ctx, authReq.RequestURI)
	if err != nil {
		return protocol.ErrInvalidRequest().WithDescription("invalid request_uri").WithParent(err)
	}

	// DEBUG: trace PAR data before merging
	slog.Info("applyPARRequest: PAR data retrieved",
		slog.Any("par_scopes", parReq.Scopes),
		slog.String("par_client_id", parReq.ClientID),
		slog.String("par_redirect_uri", parReq.RedirectURI),
		slog.Any("incoming_scopes", authReq.Scopes),
		slog.String("incoming_client_id", authReq.ClientID),
	)

	// RFC 9126: The request_uri is bound to the client that created it.
	// If the authorize endpoint carries a different client_id, reject.
	if authReq.ClientID != "" && authReq.ClientID != parReq.ClientID {
		return protocol.ErrInvalidRequest().WithDescription("client_id does not match the pushed authorization request")
	}

	// FAPI 2.0 / RFC 9126: when PAR is used, authorization parameters MUST
	// come exclusively from the pushed request. The authorize endpoint query
	// string only carries request_uri (and optionally client_id for
	// identification). All other parameters from the query string are ignored.
	// We unconditionally assign from the PAR data so that any stale
	// query-string values (e.g. state) that were not part of the pushed
	// request are cleared.
	authReq.ClientID = parReq.ClientID
	authReq.RedirectURI = parReq.RedirectURI
	authReq.Scopes = parReq.Scopes
	authReq.State = parReq.State
	authReq.ResponseType = parReq.ResponseType
	authReq.ResponseMode = parReq.ResponseMode
	if parReq.Nonce != "" && authReq.Nonce != "" && authReq.Nonce != parReq.Nonce {
		return protocol.ErrInvalidRequest().WithDescription("nonce in query does not match nonce in PAR request")
	}
	authReq.Nonce = parReq.Nonce
	authReq.Display = parReq.Display
	authReq.Prompt = parReq.Prompt
	authReq.MaxAge = parReq.MaxAge
	authReq.UILocales = parReq.UILocales
	authReq.IDTokenHint = parReq.IDTokenHint
	authReq.LoginHint = parReq.LoginHint
	authReq.ACRValues = parReq.ACRValues
	authReq.CodeChallenge = parReq.CodeChallenge
	authReq.CodeChallengeMethod = parReq.CodeChallengeMethod
	authReq.DPoPJKT = parReq.DPoPJKT
	authReq.Claims = parReq.Claims
	authReq.Resource = parReq.Resource
	authReq.AuthorizationDetails = parReq.AuthorizationDetails
	authReq.RequestParam = parReq.RequestParam

	// If the pushed request included a request object, parse and validate it.
	if authReq.RequestParam != "" {
		if err := p.applyRequestObject(ctx, authReq); err != nil {
			return err
		}
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
