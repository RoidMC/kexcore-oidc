// Package storm provides the StormEngine plugin-based OIDC server framework.
//
// StormEngine separates routing, middleware, and plugin discovery from
// OIDC protocol logic. Each OIDC feature (authorize, token, discovery, etc.)
// is implemented as an independent plugin that registers its own routes.
package storm

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
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

// StorageCapability names a storage capability interface that a plugin can
// declare as a dependency via CategorizablePlugin.Requires().
//
// Capabilities form a closed, typed enum: typos like
// []string{"UserinfoStroe"} are caught at compile time instead of silently
// disabling a plugin at Build time. CapClientStore and CapKeyStore are part
// of the base Storage contract and are always satisfied.
type StorageCapability int

const (
	// CapClientStore — client lookup + credential verification (always satisfied).
	CapClientStore StorageCapability = iota

	// CapKeyStore — JWKS publication + signing key access (always satisfied).
	CapKeyStore

	// CapAuthStore — auth request CRUD + code management.
	CapAuthStore

	// CapTokenStore — access/refresh token creation + lookup.
	CapTokenStore

	// CapUserinfoStore — populate UserInfo from tokens.
	CapUserinfoStore

	// CapIntrospectStore — RFC 7662 token introspection.
	CapIntrospectStore

	// CapRevocationStore — RFC 7009 token revocation.
	CapRevocationStore

	// CapSessionStore — session management (RP-Initiated Logout).
	CapSessionStore

	// CapDeviceAuthStore — RFC 8628 Device Authorization Grant.
	CapDeviceAuthStore

	// CapBackChannelStore — OIDC Back-Channel Logout.
	CapBackChannelStore

	// CapPARStore — RFC 9126 Pushed Authorization Requests.
	CapPARStore

	// CapDCRStore — RFC 7591 Dynamic Client Registration.
	CapDCRStore

	// CapCIBAStore — CIBA Core 1.0.
	CapCIBAStore

	// CapClientCredentialsStore — OAuth 2.0 Client Credentials Grant.
	CapClientCredentialsStore

	// CapJWTProfileStore — RFC 7523 JWT Bearer Grant.
	CapJWTProfileStore

	// CapTokenExchangeStore — RFC 8693 Token Exchange.
	CapTokenExchangeStore

	// CapTokenCNFStore — RFC 8705/9449 token binding (cnf claim).
	CapTokenCNFStore

	// CapPairwiseTransformer — OIDC Core §8.1 pairwise subject identifiers.
	CapPairwiseTransformer

	// CapAutoCompleteAuthRequest — prompt=none support (OIDC Core §3.1.2.6).
	CapAutoCompleteAuthRequest

	// CapCodeReuseDetector — RFC 6749 §4.1.2 code reuse detection.
	CapCodeReuseDetector
)

// String returns the storage interface name for the capability.
// Used in error messages so the reported name always matches storage.go.
func (c StorageCapability) String() string {
	switch c {
	case CapClientStore:
		return "ClientStore"
	case CapKeyStore:
		return "KeyStore"
	case CapAuthStore:
		return "AuthStore"
	case CapTokenStore:
		return "TokenStore"
	case CapUserinfoStore:
		return "UserinfoStore"
	case CapIntrospectStore:
		return "IntrospectStore"
	case CapRevocationStore:
		return "RevocationStore"
	case CapSessionStore:
		return "SessionStore"
	case CapDeviceAuthStore:
		return "DeviceAuthStore"
	case CapBackChannelStore:
		return "BackChannelStore"
	case CapPARStore:
		return "PARStore"
	case CapDCRStore:
		return "DCRStore"
	case CapCIBAStore:
		return "CIBAStore"
	case CapClientCredentialsStore:
		return "ClientCredentialsStore"
	case CapJWTProfileStore:
		return "JWTProfileStore"
	case CapTokenExchangeStore:
		return "TokenExchangeStore"
	case CapTokenCNFStore:
		return "TokenCNFStore"
	case CapPairwiseTransformer:
		return "PairwiseTransformer"
	case CapAutoCompleteAuthRequest:
		return "AutoCompleteAuthRequest"
	case CapCodeReuseDetector:
		return "CodeReuseDetector"
	default:
		return fmt.Sprintf("StorageCapability(%d)", int(c))
	}
}

// CategorizablePlugin is optionally implemented by plugins to declare
// their category and storage dependency requirements.
// The Engine uses this for automatic registration and ordering.
type CategorizablePlugin interface {
	Plugin

	// Category returns the plugin's registration category.
	Category() PluginCategory

	// Requires returns the set of storage capabilities this plugin needs.
	// The Engine checks whether the Storage implementation satisfies these
	// before registering the plugin. Return nil if no storage dependencies.
	// Example: []StorageCapability{CapUserinfoStore, CapIntrospectStore}
	Requires() []StorageCapability
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
