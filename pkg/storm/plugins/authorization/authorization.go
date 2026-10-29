// Package authorization implements the OIDC Authorization endpoint plugin.
//
// It handles the /authorize route (RFC 6749 Section 3.1 / OpenID Connect Core Section 3.1.1),
// covering:
//   - Parsing and validating authorization requests
//   - Redirecting to the login UI (redirect-based flow)
//   - Challenge-based REST API for external SSG Login UI
//   - Processing the callback after authentication
//   - Generating authorization codes or implicit tokens
//
// # Redirect-based flow (default)
//
// The engine creates an AuthRequest and redirects the user agent to the Login UI
// via Client.LoginURL(authRequestID). The Login UI authenticates the user and
// redirects back to /authorize/callback?id=xxx.
//
// Internal callback: GET /authorize/callback
// This is NOT an OIDC standard endpoint. It is the URL the login UI
// redirects to after successful user authentication.
//
// # Challenge-based REST API (for external SSG/SPA Login UI)
//
// The engine exposes two REST API endpoints for external Login UIs to
// accept or reject a login challenge. This is the StormEngine equivalent
// of Hydra's PUT /oauth2/auth/requests/login/accept.
//
//	POST /authorize/complete — Accept a login challenge
//	POST /authorize/reject   — Reject a login challenge
//
// The Login UI calls these endpoints after authenticating the user, and
// receives a redirect_to URL in response. It then redirects the user agent
// to that URL to complete the OIDC flow.
//
// # File layout
//
// The plugin is split by responsibility:
//   - authorization.go (this file) — plugin lifecycle, config, routing
//   - handler.go                   — HTTP handlers (authorize/callback/accept/reject)
//   - request_object.go            — Request Object / request_uri / PAR resolution
//   - response_mode.go             — response mode rendering (query/fragment/form_post/JARM)
package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/shared"
)

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
	endpointConfigs           shared.EndpointConfigMap // endpoint configurations
	createAuthCode            func(ctx context.Context, authReq storm.AuthRequest, store storm.AuthStore, enc storm.UniCrypto) (string, error)
	authorizationDetailsTypes []string                    // RFC 9396 supported types
	sessionRecorder           storm.ClientSessionRecorder // optional, for back-channel logout tracking
}

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
		endpointConfigs:   ctx.EndpointConfigs,
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
func (p *Plugin) Requires() []storm.StorageCapability {
	return []storm.StorageCapability{storm.CapAuthStore, storm.CapClientStore, storm.CapKeyStore}
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
//
// Challenge-based REST API (for external SSG Login UI):
//
//	POST /authorize/complete — Accept a login challenge.
//	  Request:  { "auth_request_id": "...", "subject": "...", "auth_time": 0, "sid": "..." }
//	  Response: { "redirect_to": "..." }
//	POST /authorize/reject — Reject a login challenge.
//	  Request:  { "auth_request_id": "...", "error": "access_denied", "error_description": "..." }
//	  Response: { "redirect_to": "..." }
func (p *Plugin) Register(r chi.Router) {
	authorizePath := p.getRoutePath("authorize", "/authorize")
	callbackPath := p.getRoutePath("authorize_callback", "/authorize/callback")
	acceptPath := p.getRoutePath("authorize_accept", "/authorize/complete")
	rejectPath := p.getRoutePath("authorize_reject", "/authorize/reject")

	r.Get(authorizePath, p.handleAuthorize)
	r.Post(authorizePath, p.handleAuthorize)
	r.Get(callbackPath, p.handleCallback)
	r.Post(acceptPath, p.handleAccept)
	r.Post(rejectPath, p.handleReject)
}

// Contribute populates the discovery fields for the authorization endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.AuthorizationEndpoint = p.resolveEndpoint(ctx, "authorize", "/authorize")

	// Authorization endpoint capabilities
	cfg.ScopesSupported = append(cfg.ScopesSupported,
		protocol.ScopeOpenID,
		protocol.ScopeProfile,
		protocol.ScopeEmail,
		protocol.ScopeAddress,
		protocol.ScopePhone,
		protocol.ScopeOfflineAccess,
	)
	cfg.ResponseTypesSupported = append(cfg.ResponseTypesSupported, string(protocol.ResponseTypeCode))
	cfg.ResponseModesSupported = append(cfg.ResponseModesSupported,
		string(protocol.ResponseModeQuery),
		string(protocol.ResponseModeFragment),
		string(protocol.ResponseModeFormPost),
	)
	cfg.GrantTypesSupported = append(cfg.GrantTypesSupported, string(protocol.GrantTypeCode))
	cfg.CodeChallengeMethodsSupported = append(cfg.CodeChallengeMethodsSupported, "S256")
	if p.allowPlainPKCE {
		cfg.CodeChallengeMethodsSupported = append(cfg.CodeChallengeMethodsSupported, "plain")
	}

	// Implicit/hybrid response types and grant type (only when enabled)
	if p.enableImplicit {
		cfg.GrantTypesSupported = append(cfg.GrantTypesSupported, string(protocol.GrantTypeImplicit))
		cfg.ResponseTypesSupported = append(cfg.ResponseTypesSupported,
			string(protocol.ResponseTypeNone),
			string(protocol.ResponseTypeIDToken),
			string(protocol.ResponseTypeToken),
			string(protocol.ResponseTypeIDTokenOnly),
			string(protocol.ResponseTypeCodeIDToken),
			string(protocol.ResponseTypeCodeToken),
			string(protocol.ResponseTypeCodeIDTokenToken),
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

// resolveEndpoint resolves the absolute URL for the given endpoint.
// If EndpointConfigs is configured, it uses that; otherwise it falls back
// to the default behavior of building the URL from the issuer in context.
func (p *Plugin) resolveEndpoint(ctx context.Context, endpointName, defaultPath string) string {
	// Check if there's a custom discovery URL configured
	if p.endpointConfigs != nil {
		defaultURL := shared.EndpointURL(ctx, protocol.NewEndpoint(defaultPath))
		return p.endpointConfigs.GetDiscoveryURL(endpointName, defaultURL)
	}
	return shared.EndpointURL(ctx, protocol.NewEndpoint(defaultPath))
}

// getRoutePath returns the route path for the given endpoint.
// If EndpointConfigs is configured, it uses that; otherwise it returns defaultPath.
func (p *Plugin) getRoutePath(endpointName, defaultPath string) string {
	if p.endpointConfigs != nil {
		return p.endpointConfigs.GetRoutePath(endpointName, defaultPath)
	}
	return defaultPath
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
