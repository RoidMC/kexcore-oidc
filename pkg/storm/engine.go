package storm

import (
	"context"
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

	disabled  map[string]bool   // plugins disabled via Disable()
	factories []PluginFactory   // plugins registered via WithPlugin()
	crypto    Crypto            // optional, for token encryption/signing
	decoder   *protocol.Decoder // optional, for form parsing
}

// DiscoveryConfig holds extra fields injected into the discovery document.
type DiscoveryConfig struct {
	ExtraFields map[string]any
}

// PluginContext provides dependencies to plugin factories.
// It wraps Storage with additional engine-level services.
type PluginContext struct {
	Storage Storage
	Crypto  Crypto // may be nil if not configured
	Decoder *protocol.Decoder
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

// WithCrypto sets the Crypto implementation for token encryption/signing.
// Plugins that need Crypto (authorization, token, introspection, userinfo, revocation)
// will receive it via PluginContext.
func WithCrypto(c Crypto) EngineOption {
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
		router:   chi.NewRouter(),
		logger:   slog.Default(),
		storage:  storage,
		issuerFn: issuerFn,
		disabled: make(map[string]bool),
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
		Storage: e.storage,
		Crypto:  e.crypto,
		Decoder: e.decoder,
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

// hasExplicitFactory checks if a plugin was explicitly added via WithPlugin.
// Currently always returns false; can be enhanced to track explicit enables.
func (e *Engine) hasExplicitFactory(name string) bool {
	// TODO: track explicit enables for optional plugins
	return false
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

	cfg := map[string]any{
		"issuer": issuer,
	}

	for _, c := range p.contributors {
		for k, v := range c.Contribute(ctx) {
			cfg[k] = v
		}
	}

	for k, v := range p.extraFields {
		cfg[k] = v
	}

	doc := &protocol.DiscoveryConfiguration{
		Issuer:                                             issuer,
		AuthorizationEndpoint:                              stringVal(cfg["authorization_endpoint"]),
		TokenEndpoint:                                      stringVal(cfg["token_endpoint"]),
		UserinfoEndpoint:                                   stringVal(cfg["userinfo_endpoint"]),
		JWKSURI:                                            stringVal(cfg["jwks_uri"]),
		RegistrationEndpoint:                               stringVal(cfg["registration_endpoint"]),
		EndSessionEndpoint:                                 stringVal(cfg["end_session_endpoint"]),
		CheckSessionIframe:                                 stringVal(cfg["check_session_iframe"]),
		BackChannelLogoutEndpoint:                          stringVal(cfg["backchannel_logout_endpoint"]),
		BackChannelLogoutSessionSupported:                  boolVal(cfg["backchannel_logout_session_supported"]),
		BackChannelLogoutSupported:                         boolVal(cfg["backchannel_logout_supported"]),
		FrontChannelLogoutEndpoint:                         stringVal(cfg["frontchannel_logout_endpoint"]),
		FrontChannelLogoutSessionSupported:                 boolVal(cfg["frontchannel_logout_session_supported"]),
		FrontChannelLogoutSupported:                        boolVal(cfg["frontchannel_logout_supported"]),
		TokenExchangeEndpoint:                              stringVal(cfg["token_exchange_endpoint"]),
		DeviceAuthorizationEndpoint:                        stringVal(cfg["device_authorization_endpoint"]),
		PushedAuthorizationRequestEndpoint:                 stringVal(cfg["pushed_authorization_request_endpoint"]),
		RequirePushedAuthorizationRequests:                 boolVal(cfg["require_pushed_authorization_requests"]),
		IntrospectionEndpoint:                              stringVal(cfg["introspection_endpoint"]),
		RevocationEndpoint:                                 stringVal(cfg["revocation_endpoint"]),
		ScopesSupported:                                    stringSliceVal(cfg["scopes_supported"]),
		ResponseTypesSupported:                             stringSliceVal(cfg["response_types_supported"]),
		ResponseModesSupported:                             stringSliceVal(cfg["response_modes_supported"]),
		GrantTypesSupported:                                stringSliceVal(cfg["grant_types_supported"]),
		ACRValuesSupported:                                 stringSliceVal(cfg["acr_values_supported"]),
		SubjectTypesSupported:                              stringSliceVal(cfg["subject_types_supported"]),
		IDTokenSigningAlgValuesSupported:                   stringSliceVal(cfg["id_token_signing_alg_values_supported"]),
		IDTokenEncryptionAlgValuesSupported:                stringSliceVal(cfg["id_token_encryption_alg_values_supported"]),
		IDTokenEncryptionEncValuesSupported:                stringSliceVal(cfg["id_token_encryption_enc_values_supported"]),
		UserinfoSigningAlgValuesSupported:                  stringSliceVal(cfg["userinfo_signing_alg_values_supported"]),
		UserinfoEncryptionAlgValuesSupported:               stringSliceVal(cfg["userinfo_encryption_alg_values_supported"]),
		UserinfoEncryptionEncValuesSupported:               stringSliceVal(cfg["userinfo_encryption_enc_values_supported"]),
		RequestObjectSigningAlgValuesSupported:             stringSliceVal(cfg["request_object_signing_alg_values_supported"]),
		RequestObjectEncryptionAlgValuesSupported:          stringSliceVal(cfg["request_object_encryption_alg_values_supported"]),
		RequestObjectEncryptionEncValuesSupported:          stringSliceVal(cfg["request_object_encryption_enc_values_supported"]),
		TokenEndpointAuthMethodsSupported:                  stringSliceVal(cfg["token_endpoint_auth_methods_supported"]),
		TokenEndpointAuthSigningAlgValuesSupported:         stringSliceVal(cfg["token_endpoint_auth_signing_alg_values_supported"]),
		IntrospectionEndpointAuthMethodsSupported:          stringSliceVal(cfg["introspection_endpoint_auth_methods_supported"]),
		IntrospectionEndpointAuthSigningAlgValuesSupported: stringSliceVal(cfg["introspection_endpoint_auth_signing_alg_values_supported"]),
		RevocationEndpointAuthMethodsSupported:             stringSliceVal(cfg["revocation_endpoint_auth_methods_supported"]),
		RevocationEndpointAuthSigningAlgValuesSupported:    stringSliceVal(cfg["revocation_endpoint_auth_signing_alg_values_supported"]),
		DisplayValuesSupported:                             stringSliceVal(cfg["display_values_supported"]),
		ClaimTypesSupported:                                stringSliceVal(cfg["claim_types_supported"]),
		ClaimsSupported:                                    stringSliceVal(cfg["claims_supported"]),
		ClaimsParameterSupported:                           boolVal(cfg["claims_parameter_supported"]),
		ClaimsLocalesSupported:                             stringSliceVal(cfg["claims_locales_supported"]),
		UILocalesSupported:                                 stringSliceVal(cfg["ui_locales_supported"]),
		RequestParameterSupported:                          boolVal(cfg["request_parameter_supported"]),
		RequestURIParameterSupported:                       boolVal(cfg["request_uri_parameter_supported"]),
		RequireRequestURIRegistration:                      boolVal(cfg["require_request_uri_registration"]),
		CodeChallengeMethodsSupported:                      stringSliceVal(cfg["code_challenge_methods_supported"]),
		AuthorizationResponseISSParameterSupported:         boolVal(cfg["authorization_response_iss_parameter_supported"]),
		ServiceDocumentation:                               stringVal(cfg["service_documentation"]),
		OPPolicyURI:                                        stringVal(cfg["op_policy_uri"]),
		OPTermsOfServiceURI:                                stringVal(cfg["op_tos_uri"]),
		JWEAlgValuesSupported:                              stringSliceVal(cfg["jwe_alg_values_supported"]),
		JWEEncValuesSupported:                              stringSliceVal(cfg["jwe_enc_values_supported"]),
		TLSClientCertificateBoundAccessTokens:              boolVal(cfg["tls_client_certificate_bound_access_tokens"]),
		MTLSEndpointAliases:                                cfg["mtls_endpoint_aliases"],
		Extra:                                              make(map[string]any),
	}

	skip := map[string]bool{
		"issuer": true, "authorization_endpoint": true, "token_endpoint": true,
		"userinfo_endpoint": true, "jwks_uri": true, "registration_endpoint": true,
		"end_session_endpoint": true, "check_session_iframe": true,
		"backchannel_logout_endpoint": true, "backchannel_logout_session_supported": true,
		"backchannel_logout_supported": true, "frontchannel_logout_endpoint": true,
		"frontchannel_logout_session_supported": true, "frontchannel_logout_supported": true,
		"token_exchange_endpoint": true, "device_authorization_endpoint": true,
		"pushed_authorization_request_endpoint": true, "require_pushed_authorization_requests": true,
		"introspection_endpoint": true, "revocation_endpoint": true,
		"scopes_supported": true, "response_types_supported": true,
		"response_modes_supported": true, "grant_types_supported": true,
		"acr_values_supported": true, "subject_types_supported": true,
		"id_token_signing_alg_values_supported":                    true,
		"id_token_encryption_alg_values_supported":                 true,
		"id_token_encryption_enc_values_supported":                 true,
		"userinfo_signing_alg_values_supported":                    true,
		"userinfo_encryption_alg_values_supported":                 true,
		"userinfo_encryption_enc_values_supported":                 true,
		"request_object_signing_alg_values_supported":              true,
		"request_object_encryption_alg_values_supported":           true,
		"request_object_encryption_enc_values_supported":           true,
		"token_endpoint_auth_methods_supported":                    true,
		"token_endpoint_auth_signing_alg_values_supported":         true,
		"introspection_endpoint_auth_methods_supported":            true,
		"introspection_endpoint_auth_signing_alg_values_supported": true,
		"revocation_endpoint_auth_methods_supported":               true,
		"revocation_endpoint_auth_signing_alg_values_supported":    true,
		"display_values_supported":                                 true, "claim_types_supported": true,
		"claims_supported": true, "claims_parameter_supported": true,
		"claims_locales_supported": true, "ui_locales_supported": true,
		"request_parameter_supported": true, "request_uri_parameter_supported": true,
		"require_request_uri_registration":               true,
		"code_challenge_methods_supported":               true,
		"authorization_response_iss_parameter_supported": true,
		"service_documentation":                          true, "op_policy_uri": true, "op_tos_uri": true,
		"jwe_alg_values_supported": true, "jwe_enc_values_supported": true,
		"tls_client_certificate_bound_access_tokens": true, "mtls_endpoint_aliases": true,
	}
	for k, v := range cfg {
		if !skip[k] {
			doc.Extra[k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.Encode(doc)
}

func boolVal(v any) bool {
	b, _ := v.(bool)
	return b
}

func stringVal(v any) string {
	s, _ := v.(string)
	return s
}

func stringSliceVal(v any) []string {
	s, _ := v.([]string)
	return s
}
