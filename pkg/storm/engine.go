package storm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/roidmc/kexcore-oidc/internal/otel"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Engine is the core orchestrator for StormEngine.
// It manages plugin registration, route assembly, middleware application,
// and discovery document collision detection.
//
// Engine does not know anything about OIDC. It is a pure HTTP framework
// that delegates all protocol logic to registered plugins.
type Engine struct {
	router     chi.Router
	handler    http.Handler
	plugins    []Plugin
	middleware []func(http.Handler) http.Handler
	corsOpts   *cors.Options
	logger     *slog.Logger
	tracer     trace.Tracer

	storage      Storage
	issuerFn     shared.IssuerFromRequest
	discoveryCfg DiscoveryConfig

	disabled          map[string]bool   // plugins disabled via Disable()
	explicitlyEnabled map[string]bool   // plugins explicitly enabled via Enable()
	factories         []PluginFactory   // plugins registered via WithPlugin()
	crypto            UniCrypto         // optional, for token encryption/signing
	decoder           *protocol.Decoder // optional, for form parsing
	enableImplicit    bool              // enable implicit/hybrid flows
	allowPlainPKCE    bool              // allow plain code_challenge_method
	allowPrivateIPs   bool              // allow private/link-local IPs in jwks_uri etc.
	skipTLSCertVerify bool              // skip TLS cert verification on outbound HTTP
	requireDPoP       bool              // FAPI 2.0: require DPoP for token requests
	requireMtls       bool              // FAPI 2.0: require mTLS for token requests
	parLifetime       time.Duration     // PAR request_uri lifetime (default: 90s)
}

// DiscoveryConfig holds extra fields injected into the discovery document.
type DiscoveryConfig struct {
	ExtraFields map[string]any
}

// PluginContext provides dependencies to plugin factories.
// It wraps Storage with additional engine-level services.
type PluginContext struct {
	Storage         Storage
	Crypto          UniCrypto // may be nil if not configured
	Decoder         *protocol.Decoder
	EnableImplicit  bool // enable implicit/hybrid flows (disabled by default per OAuth 2.1)
	AllowPlainPKCE  bool // allow plain code_challenge_method (disabled by default per OAuth 2.1)
	AllowPrivateIPs bool // WARNING: disables SSRF protection in DCR (jwks_uri, sector_identifier_uri).
	// Only for testing with private-network conformance suites.
	// NEVER enable in production — use network-level controls instead.
	SkipTLSCertVerify bool // WARNING: disables TLS certificate verification on outbound HTTP requests.
	// Only for testing with self-signed certificates.
	// NEVER enable in production.
	RequireDPoP bool                     // FAPI 2.0: require DPoP proof for all token requests
	RequireMtls bool                     // FAPI 2.0: require mTLS client certificate for all token requests
	PARLifetime time.Duration            // PAR request_uri lifetime (default: 0 means use plugin default, usually 90s)
	IssuerFn    shared.IssuerFromRequest // issuer URL function
	Tracer      trace.Tracer             // otel tracer for plugins
}

// PluginFactory creates a plugin from a PluginContext.
// Used by WithPlugin and RegisterPlugin for deferred plugin construction.
type PluginFactory func(ctx *PluginContext) Plugin

// globalRegistry holds plugin factories registered via RegisterPlugin.
// This enables automatic plugin discovery without import-time side effects.
var globalRegistry = []struct {
	name     string
	factory  PluginFactory
	priority int // lower = registered earlier
}{}

// PluginPriority defines registration ordering.
// Core plugins use lower numbers; optional plugins use higher numbers.
const (
	PriorityAuthorization = 100
	PriorityToken         = 200
	PriorityKeys          = 300
	PriorityDiscovery     = 400
	PriorityUserinfo      = 500
	PriorityIntrospection = 600
	PriorityRevocation    = 700
	PriorityEndSession    = 800
	PriorityBackChannel   = 850
	PriorityDevice        = 900
	PriorityPAR           = 950
	PriorityDPoP          = 960
	PriorityMTLS          = 970
	PriorityJARM          = 975
	PriorityDCR           = 1000
	PriorityCIBA          = 1050
	PriorityWebFinger     = 1100
)

// RegisterPlugin registers a plugin factory in the global registry.
// Call this in init() or at package level. Plugins are auto-discovered
// by New() and sorted by priority.
func RegisterPlugin(name string, priority int, factory PluginFactory) {
	globalRegistry = append(globalRegistry, struct {
		name     string
		factory  PluginFactory
		priority int
	}{name, factory, priority})
}

// WithPlugin adds a plugin factory to the Engine.
// The factory is called during Build() with the Engine's Storage.
func WithPlugin(factory PluginFactory) EngineOption {
	return func(e *Engine) {
		e.factories = append(e.factories, factory)
	}
}

// Disable prevents the named plugins from being registered.
// Only affects Standard and Optional plugins; Core plugins cannot be disabled.
func Disable(names ...string) EngineOption {
	return func(e *Engine) {
		if e.disabled == nil {
			e.disabled = make(map[string]bool)
		}
		for _, name := range names {
			e.disabled[name] = true
		}
	}
}

// Enable explicitly enables named plugins that would otherwise not be registered.
// This is primarily used for Optional plugins (CategoryOptional) which are
// skipped by default unless explicitly enabled.
func Enable(names ...string) EngineOption {
	return func(e *Engine) {
		if e.explicitlyEnabled == nil {
			e.explicitlyEnabled = make(map[string]bool)
		}
		for _, name := range names {
			e.explicitlyEnabled[name] = true
		}
	}
}

// EngineOption configures an Engine.
type EngineOption func(*Engine)

// WithCORS sets the CORS policy for the engine.
func WithCORS(opts *cors.Options) EngineOption {
	return func(e *Engine) {
		e.corsOpts = opts
	}
}

// WithMiddleware appends middleware to the engine's middleware chain.
// Middleware is applied in the order given, wrapping the final handler.
func WithMiddleware(mw ...func(http.Handler) http.Handler) EngineOption {
	return func(e *Engine) {
		e.middleware = append(e.middleware, mw...)
	}
}

// WithLogger sets the logger used by the engine.
func WithLogger(logger *slog.Logger) EngineOption {
	return func(e *Engine) {
		e.logger = logger
	}
}

// WithCrypto sets the UniCrypto implementation for token encryption/signing.
// Plugins that need Crypto (authorization, token, introspection, userinfo, revocation)
// will receive it via PluginContext.
func WithCrypto(c UniCrypto) EngineOption {
	return func(e *Engine) {
		e.crypto = c
	}
}

// WithDecoder sets the protocol decoder for form parsing.
// If not set, a default decoder is created.
func WithDecoder(d *protocol.Decoder) EngineOption {
	return func(e *Engine) {
		e.decoder = d
	}
}

// WithDiscoveryConfig sets extra fields injected into the discovery document.
func WithDiscoveryConfig(cfg DiscoveryConfig) EngineOption {
	return func(e *Engine) {
		e.discoveryCfg = cfg
	}
}

// WithImplicit enables the Implicit and Hybrid flows.
// Disabled by default per OAuth 2.1.
func WithImplicit() EngineOption {
	return func(e *Engine) {
		e.enableImplicit = true
	}
}

// WithPlainPKCE enables the "plain" code_challenge_method (RFC 7636).
// Disabled by default per OAuth 2.1 §4.1.1. Call this to allow clients
// to use code_challenge_method=plain when they explicitly opt in.
func WithPlainPKCE() EngineOption {
	return func(e *Engine) {
		e.allowPlainPKCE = true
	}
}

// WithAllowPrivateIPs disables SSRF protection in DCR (jwks_uri,
// sector_identifier_uri). Use ONLY for testing with self-hosted conformance
// suites on private networks. NEVER enable in production.
//
// For production deployments that need to allow specific private CIDRs,
// handle this at the network layer (firewall / reverse proxy) instead.
func WithAllowPrivateIPs() EngineOption {
	return func(e *Engine) {
		e.allowPrivateIPs = true
	}
}

// WithSkipTLSCertVerify disables TLS certificate verification on outbound
// HTTP requests (JWKS fetches, request_uri, backchannel_logout, etc.).
// Use ONLY for testing with self-signed certificates. NEVER enable in production.
func WithSkipTLSCertVerify() EngineOption {
	return func(e *Engine) {
		e.skipTLSCertVerify = true
	}
}

// WithRequireDPoP enables FAPI 2.0 DPoP sender-constrained tokens.
func WithRequireDPoP() EngineOption {
	return func(e *Engine) {
		e.requireDPoP = true
	}
}

// WithRequireMtls enables FAPI 2.0 mTLS sender-constrained tokens.
func WithRequireMtls() EngineOption {
	return func(e *Engine) {
		e.requireMtls = true
	}
}

// WithPARLifetime sets the lifetime for pushed authorization request URIs.
// If not set, the PAR plugin uses its own default (typically 90s).
func WithPARLifetime(d time.Duration) EngineOption {
	return func(e *Engine) {
		e.parLifetime = d
	}
}

// New creates a new Engine with the given storage and issuer function.
//
// The issuerFn is used to inject the issuer into the request context
// and into the discovery document.
//
// Plugins are registered from two sources:
//  1. Global registry (via RegisterPlugin) — auto-discovered and sorted by priority
//  2. WithPlugin option factories — registered after global plugins
//
// Use Disable() to prevent specific Standard/Optional plugins from loading.
func New(storage Storage, issuerFn shared.IssuerFromRequest, opts ...EngineOption) *Engine {
	e := &Engine{
		router:            chi.NewRouter(),
		logger:            slog.Default(),
		tracer:            otel.Tracer("github.com/roidmc/kexcore-oidc/pkg/storm"),
		storage:           storage,
		issuerFn:          issuerFn,
		disabled:          make(map[string]bool),
		explicitlyEnabled: make(map[string]bool),
	}
	for _, opt := range opts {
		opt(e)
	}
	e.autoRegisterPlugins()
	return e
}

// autoRegisterPlugins discovers plugins from the global registry,
// filters disabled ones, checks storage dependencies, and registers
// them in priority order.
func (e *Engine) autoRegisterPlugins() {
	// Build plugin context with all dependencies
	pctx := &PluginContext{
		Storage:           e.storage,
		Crypto:            e.crypto,
		Decoder:           e.decoder,
		EnableImplicit:    e.enableImplicit,
		AllowPlainPKCE:    e.allowPlainPKCE,
		AllowPrivateIPs:   e.allowPrivateIPs,
		SkipTLSCertVerify: e.skipTLSCertVerify,
		RequireDPoP:       e.requireDPoP,
		RequireMtls:       e.requireMtls,
		PARLifetime:       e.parLifetime,
		IssuerFn:          e.issuerFn,
		Tracer:            e.tracer,
	}
	if pctx.Decoder == nil {
		pctx.Decoder = protocol.NewDecoder()
	}

	// Collect all candidate plugins (global + explicit factories)
	type candidate struct {
		name     string
		factory  PluginFactory
		priority int
	}
	var candidates []candidate

	// Global registry plugins
	for _, reg := range globalRegistry {
		candidates = append(candidates, candidate{
			name:     reg.name,
			factory:  reg.factory,
			priority: reg.priority,
		})
	}

	// Explicitly added factories (use max priority so they register after globals)
	for _, f := range e.factories {
		candidates = append(candidates, candidate{
			name:     "custom",
			factory:  f,
			priority: 9999,
		})
	}

	// Sort by priority
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].priority < candidates[j].priority
	})

	// Register each plugin
	for _, c := range candidates {
		// Check if disabled
		if e.disabled[c.name] {
			e.logger.Info("plugin disabled", "name", c.name)
			continue
		}

		p := c.factory(pctx)
		if p == nil {
			e.logger.Warn("plugin factory returned nil, skipping", "name", c.name)
			continue
		}

		// Check CategorizablePlugin for category-based disable
		if cp, ok := p.(CategorizablePlugin); ok {
			cat := cp.Category()
			if cat == CategoryOptional && !e.hasExplicitFactory(c.name) {
				e.logger.Debug("optional plugin not explicitly enabled, skipping", "name", c.name)
				continue
			}
			// Core plugins cannot be disabled
			if cat == CategoryCore && e.disabled[c.name] {
				e.logger.Warn("cannot disable core plugin", "name", c.name)
			}
		}

		e.plugins = append(e.plugins, p)
		p.Register(e.router)
		e.logger.Info("plugin registered", "name", p.Name())
	}
}

// hasExplicitFactory checks if a plugin was explicitly enabled via Enable().
// This is used to determine if Optional plugins should be registered.
func (e *Engine) hasExplicitFactory(name string) bool {
	return e.explicitlyEnabled[name]
}

// Register adds a plugin to the engine.
// The plugin's routes are immediately installed on the internal router.
//
// Name collisions are not checked here; they are detected at Build time
// via discovery document collision detection.
func (e *Engine) Register(p Plugin) {
	e.plugins = append(e.plugins, p)
	p.Register(e.router)
	e.logger.Info("plugin registered", "name", p.Name())
}

// Build finalizes the engine by:
//  1. Installing the built-in /healthz and /ready handlers
//  2. Installing the discovery aggregator
//  3. Detecting discovery key collisions across all DiscoveryContributor plugins
//  4. Applying CORS and user middleware
//
// If discovery key collisions are detected, Build panics.
// This is intentional: collisions indicate a configuration error that
// must be fixed before the server can start.
func (e *Engine) Build() http.Handler {
	// Built-in health endpoints
	e.router.Get("/healthz", e.healthHandler)
	e.router.Get("/ready", e.readyHandler)

	// Auto-connect EndSession and BackChannel plugins if both exist.
	// BackChannel implements LogoutHook, so EndSession can trigger it.
	e.connectLogoutHooks()

	// Auto-connect Authorization and JARM plugins if both exist.
	// JARM implements JARMSigner, so Authorization can sign responses.
	e.connectJARMSigner()

	// Auto-connect Token and DPoP plugins if both exist.
	// DPoP implements DPoPNonceSender, so Token can include DPoP-Nonce headers.
	e.connectDPoPNonceSender()

	// Discovery aggregation
	e.installDiscovery()

	// Validate plugin registration and storage compatibility.
	// Fail fast if constraints are violated.
	if err := e.Validate(); err != nil {
		if e.logger != nil {
			e.logger.Error("engine validation failed", "error", err)
		}
		panic(fmt.Sprintf("storm: engine validation failed: %s", err))
	}

	e.logPluginInfo()

	// Apply middleware (CORS first, then otel, then plugin middleware, then user middleware)
	var h http.Handler = e.router
	if e.corsOpts != nil {
		h = cors.New(*e.corsOpts).Handler(h)
	}
	h = e.otelMiddleware(h)
	// Auto-apply middleware from plugins that implement MiddlewareProvider.
	for _, p := range e.plugins {
		if mp, ok := p.(MiddlewareProvider); ok {
			h = mp.Middleware(h)
			e.logger.Info("applied plugin middleware", "name", p.Name())
		}
	}
	for _, mw := range e.middleware {
		h = mw(h)
	}
	e.handler = h
	return h
}

// Handler returns the built handler.
// Must be called after Build.
func (e *Engine) Handler() http.Handler {
	if e.handler == nil {
		panic("storm: Engine.Build() must be called before Handler()")
	}
	return e.handler
}

// Plugins returns a snapshot of registered plugins.
func (e *Engine) Plugins() []Plugin {
	out := make([]Plugin, len(e.plugins))
	copy(out, e.plugins)
	return out
}

// Storage returns the engine's storage.
func (e *Engine) Storage() Storage {
	return e.storage
}

// --- internal ---

// otelMiddleware creates an HTTP middleware that adds OpenTelemetry tracing.
func (e *Engine) otelMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := e.tracer.Start(r.Context(), r.Method+" "+r.URL.Path,
			trace.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.url", r.URL.String()),
				attribute.String("http.user_agent", r.UserAgent()),
				attribute.String("http.remote_addr", r.RemoteAddr),
			),
		)
		defer span.End()

		r = r.WithContext(ctx)

		// Wrap response writer to capture status code
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(ww, r)

		span.SetAttributes(
			attribute.Int("http.status_code", ww.statusCode),
		)

		if ww.statusCode >= 400 {
			span.SetStatus(codes.Error, http.StatusText(ww.statusCode))
		}
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (e *Engine) healthHandler(w http.ResponseWriter, r *http.Request) {
	shared.JSONResponse(w, map[string]string{"status": "ok"}, http.StatusOK)
}

func (e *Engine) readyHandler(w http.ResponseWriter, r *http.Request) {
	if err := e.storage.Health(r.Context()); err != nil {
		shared.JSONResponse(w, map[string]string{"status": "not ready", "error": err.Error()}, http.StatusServiceUnavailable)
		return
	}
	shared.JSONResponse(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// connectLogoutHooks auto-connects EndSession and BackChannel plugins.
// If both plugins are registered and BackChannel implements LogoutHook,
// it is automatically set as EndSession's logout hook.
func (e *Engine) connectLogoutHooks() {
	// Type for checking if a plugin can set a logout hook
	type logoutHookSetter interface {
		SetLogoutHook(hook interface{})
	}

	var endSession logoutHookSetter
	var backChannel interface{}

	for _, p := range e.plugins {
		switch p.Name() {
		case "endsession":
			if setter, ok := p.(logoutHookSetter); ok {
				endSession = setter
			}
		case "backchannel":
			backChannel = p
		}
	}

	// If both exist, connect them
	if endSession != nil && backChannel != nil {
		// Check if backChannel implements PostLogout method
		type logoutHookProvider interface {
			PostLogout(ctx context.Context, userID, clientID, sid string)
		}
		if provider, ok := backChannel.(logoutHookProvider); ok {
			endSession.SetLogoutHook(provider)
			e.logger.Info("connected backchannel logout hook to endsession")
		}
	}
}

// connectJARMSigner auto-connects Authorization and JARM plugins.
// If both plugins are registered and JARM implements JARMSigner,
// it is automatically set as Authorization's JARM signer.
func (e *Engine) connectJARMSigner() {
	// Type for checking if a plugin can set a JARM signer
	type jarmSignerSetter interface {
		SetJARMSigner(signer JARMSigner)
	}

	var authorization jarmSignerSetter
	var jarmPlugin JARMSigner

	for _, p := range e.plugins {
		switch p.Name() {
		case "authorization":
			if setter, ok := p.(jarmSignerSetter); ok {
				authorization = setter
			}
		case "jarm":
			if signer, ok := p.(JARMSigner); ok {
				jarmPlugin = signer
			}
		}
	}

	// If both exist, connect them
	if authorization != nil && jarmPlugin != nil {
		authorization.SetJARMSigner(jarmPlugin)
		e.logger.Info("connected JARM signer to authorization")
	}
}

// connectDPoPNonceSender auto-connects Token and DPoP plugins.
// If both plugins are registered and DPoP implements DPoPNonceSender,
// it is automatically set as Token's DPoP nonce sender (RFC 9449 §8).
func (e *Engine) connectDPoPNonceSender() {
	type dpopNonceSetter interface {
		SetDPoPNonceSender(sender interface {
			WriteNonceHeader(w http.ResponseWriter)
		})
	}

	var tokenPlugin dpopNonceSetter
	var dpopPlugin interface {
		WriteNonceHeader(w http.ResponseWriter)
	}

	for _, p := range e.plugins {
		switch p.Name() {
		case "token":
			if setter, ok := p.(dpopNonceSetter); ok {
				tokenPlugin = setter
			}
		case "dpop":
			if sender, ok := p.(interface {
				WriteNonceHeader(w http.ResponseWriter)
			}); ok {
				dpopPlugin = sender
			}
		}
	}

	if tokenPlugin != nil && dpopPlugin != nil {
		tokenPlugin.SetDPoPNonceSender(dpopPlugin)
		e.logger.Info("connected DPoP nonce sender to token")
	}
}

func (e *Engine) installDiscovery() {
	// Collect all DiscoveryContributor plugins
	var contributors []DiscoveryContributor
	for _, p := range e.plugins {
		if dc, ok := p.(DiscoveryContributor); ok {
			contributors = append(contributors, dc)
		}
	}

	dp := &discoveryPlugin{
		issuerFn:     e.issuerFn,
		contributors: contributors,
		extraFields:  e.discoveryCfg.ExtraFields,
	}
	dp.Register(e.router)
}

// discoveryPlugin is the internal plugin that serves the discovery document.
type discoveryPlugin struct {
	issuerFn     shared.IssuerFromRequest
	contributors []DiscoveryContributor
	extraFields  map[string]any
}

func (p *discoveryPlugin) Name() string { return "discovery" }

func (p *discoveryPlugin) Register(r chi.Router) {
	r.Get("/.well-known/openid-configuration", p.handle)
}

func (p *discoveryPlugin) handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	issuer := p.issuerFn(r)
	ctx = shared.ContextWithIssuer(ctx, issuer)

	cfg := &protocol.DiscoveryConfiguration{
		Issuer: issuer,
		Extra:  make(map[string]any),
	}

	for _, c := range p.contributors {
		c.Contribute(ctx, cfg)
	}

	for k, v := range p.extraFields {
		cfg.Extra[k] = v
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}
