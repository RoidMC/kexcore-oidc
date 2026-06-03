// Package storm provides the StormEngine plugin-based OIDC server framework.
//
// StormEngine separates routing, middleware, and plugin discovery from
// OIDC protocol logic. Each OIDC feature (authorize, token, discovery, etc.)
// is implemented as an independent plugin that registers its own routes.
package storm

import (
	"context"

	"github.com/go-chi/chi/v5"
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
// The Engine collects contributions from all registered plugins and
// performs collision detection at build time. If two plugins contribute
// the same key, Build panics — this prevents silent overwrites.
//
// Rules for plugins:
//
//  1. Standard keys that match protocol.DiscoveryConfiguration fields
//     SHOULD use the same JSON tag as the struct (e.g. "authorization_endpoint").
//     The Engine populates these directly into typed struct fields.
//
//  2. Custom/extension keys (e.g. "my_extension_field") SHOULD be prefixed
//     to avoid collisions and WILL end up in the Extra map.
//
//  3. Keys contributed by plugins take precedence over Engine defaults.
//     The plugin that registers first wins when duplicates are detected.
//
//  4. The ctx parameter contains the issuer via shared.IssuerFromContext(ctx),
//     allowing plugins to build absolute endpoint URLs.
type DiscoveryContributor interface {
	Plugin

	// Contribute returns key-value pairs for the discovery document.
	// Keys must follow OIDC Discovery naming conventions.
	// ctx contains the issuer via shared.IssuerFromContext.
	Contribute(ctx context.Context) map[string]any
}
