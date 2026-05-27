package storm

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"

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

	storage  Storage
	issuerFn shared.IssuerFromRequest
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

// New creates a new Engine with the given storage and issuer function.
//
// The issuerFn is used to inject the issuer into the request context
// and into the discovery document.
func New(storage Storage, issuerFn shared.IssuerFromRequest, opts ...EngineOption) *Engine {
	e := &Engine{
		router:   chi.NewRouter(),
		logger:   slog.Default(),
		storage:  storage,
		issuerFn: issuerFn,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
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
//   1. Installing the built-in /healthz and /ready handlers
//   2. Installing the discovery aggregator
//   3. Detecting discovery key collisions across all DiscoveryContributor plugins
//   4. Applying CORS and user middleware
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

	// Collision detection: every key must be unique
	seen := make(map[string]string) // key -> plugin name
	for _, c := range contributors {
		// Use a background context for pre-flight key enumeration.
		// Actual values are resolved at request time.
		for k := range c.Contribute(context.Background()) {
			if prev, exists := seen[k]; exists {
				panic(fmt.Sprintf(
					"storm: discovery key collision: %q declared by both %q and %q",
					k, prev, c.Name(),
				))
			}
			seen[k] = c.Name()
		}
	}

	dp := &discoveryPlugin{
		issuerFn:     e.issuerFn,
		contributors: contributors,
	}
	dp.Register(e.router)
}

// discoveryPlugin is the internal plugin that serves the discovery document.
type discoveryPlugin struct {
	issuerFn     shared.IssuerFromRequest
	contributors []DiscoveryContributor
}

func (p *discoveryPlugin) Name() string { return "discovery" }

func (p *discoveryPlugin) Register(r chi.Router) {
	r.Get("/.well-known/openid-configuration", p.handle)
}

func (p *discoveryPlugin) handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	issuer := p.issuerFn(r)
	ctx = shared.ContextWithIssuer(ctx, issuer)

	cfg := map[string]any{
		"issuer": issuer,
	}

	for _, c := range p.contributors {
		for k, v := range c.Contribute(ctx) {
			cfg[k] = v
		}
	}

	shared.JSONResponse(w, cfg, http.StatusOK)
}