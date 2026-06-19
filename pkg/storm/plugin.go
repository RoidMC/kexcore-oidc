// Package storm provides the StormEngine plugin-based OIDC server framework.
//
// StormEngine separates routing, middleware, and plugin discovery from
// OIDC protocol logic. Each OIDC feature (authorize, token, discovery, etc.)
// is implemented as an independent plugin that registers its own routes.
package storm

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
)

// PluginCategory defines the lifecycle and registration behavior of a plugin.
type PluginCategory int

const (
	// CategoryCore plugins are always registered and cannot be disabled.
	// They form the minimum viable OIDC server (authorization, token, keys, discovery).
	CategoryCore PluginCategory = iota

	// CategoryStandard plugins are registered by default when their Storage
	// dependencies are satisfied. Users can disable them via Disable().
	CategoryStandard

	// CategoryOptional plugins are only registered when explicitly enabled
	// by the user via WithPlugin() or specific option functions.
	CategoryOptional
)

// Plugin is the fundamental unit of a StormEngine server.
// Each plugin owns its routes, request parsing, business logic,
// and error handling. The Engine does not interpret OIDC semantics.
//
// Plugin.Name() must be unique across all registered plugins.
type Plugin interface {
	// Name returns the plugin's unique identifier.
	// Used for logging and conflict detection.
	Name() string

	// Register installs the plugin's HTTP handlers on the given router.
	// The plugin has full control over routing and handler behavior.
	Register(r chi.Router)
}

// CategorizablePlugin is optionally implemented by plugins to declare
// their category and storage dependency requirements.
// The Engine uses this for automatic registration and ordering.
type CategorizablePlugin interface {
	Plugin

	// Category returns the plugin's registration category.
	Category() PluginCategory

	// Requires returns the set of storage interface names this plugin needs.
	// The Engine checks whether the Storage implementation satisfies these
	// before registering the plugin. Return nil if no storage dependencies.
	// Example: []string{"UserinfoStore", "IntrospectStore"}
	Requires() []string
}

// DiscoveryContributor is an optional interface that plugins may implement
// to contribute fields to the openid-configuration discovery document.
//
// The Engine creates a protocol.DiscoveryConfiguration, calls each
// contributor's Contribute method in registration order, then serializes
// the result. Plugins set fields directly on the typed struct — no magic
// strings, no map round-trips.
//
// Rules for plugins:
//
//  1. Only set fields owned by your plugin. Do not overwrite fields
//     set by other plugins.
//
//  2. Custom/extension fields that don't map to DiscoveryConfiguration
//     struct fields should be placed in cfg.Extra.
//
//  3. The ctx parameter contains the issuer via shared.IssuerFromContext(ctx),
//     allowing plugins to build absolute endpoint URLs.
type DiscoveryContributor interface {
	Plugin

	// Contribute populates discovery fields on the given configuration.
	// Plugins should only set the fields they own.
	// ctx contains the issuer via shared.IssuerFromContext.
	Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration)
}

// MiddlewareProvider is optionally implemented by plugins that provide
// HTTP middleware to be applied to all requests. The engine auto-detects
// this interface during Build() and applies the middleware to the pipeline.
//
// Example: DPoP plugin provides middleware to parse DPoP proofs from
// request headers and store them in the request context.
type MiddlewareProvider interface {
	Plugin

	// Middleware wraps the given handler with plugin-specific middleware.
	Middleware(next http.Handler) http.Handler
}
