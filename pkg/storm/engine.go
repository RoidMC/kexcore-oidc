package storm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"

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

	storage      Storage
	issuerFn     shared.IssuerFromRequest
	discoveryCfg DiscoveryConfig

	disabled          map[string]bool   // plugins disabled via Disable()
	explicitlyEnabled map[string]bool   // plugins explicitly enabled via Enable()
	factories         []PluginFactory   // plugins registered via WithPlugin()
	crypto            UniCrypto         // optional, for token encryption/signing
	decoder           *protocol.Decoder // optional, for form parsing
	enableImplicit    bool              // enable implicit/hybrid flows
}

// DiscoveryConfig holds extra fields injected into the discovery document.
type DiscoveryConfig struct {
	ExtraFields map[string]any
}

// PluginContext provides dependencies to plugin factories.
// It wraps Storage with additional engine-level services.
type PluginContext struct {
	Storage        Storage
	Crypto         UniCrypto // may be nil if not configured
	Decoder        *protocol.Decoder
	EnableImplicit bool // enable implicit/hybrid flows (disabled by default per OAuth 2.1)
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
	PriorityDCR           = 1000
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
		Storage:        e.storage,
		Crypto:         e.crypto,
		Decoder:        e.decoder,
		EnableImplicit: e.enableImplicit,
	}
	if pctx.Decoder == nil {
		pctx.Decoder = protocol.NewDecoder()
		pctx.Decoder.IgnoreUnknownKeys(true)
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

	// Apply middleware (CORS first, then user middleware)
	var h http.Handler = e.router
	if e.corsOpts != nil {
		h = cors.New(*e.corsOpts).Handler(h)
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
