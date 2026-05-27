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

// DiscoveryContributor is an optional interface that plugins may implement
// to contribute fields to the openid-configuration discovery document.
//
// The Engine collects contributions from all registered plugins and
// performs collision detection at build time.
type DiscoveryContributor interface {
	Plugin

	// Contribute returns key-value pairs for the discovery document.
	// Keys must follow OIDC Discovery naming conventions.
	// ctx contains the issuer via shared.IssuerFromContext.
	Contribute(ctx context.Context) map[string]any
}