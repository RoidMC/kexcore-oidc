// Package discovery implements the OIDC Discovery capability contributor plugin.
//
// This plugin contributes algorithm-related fields (derived from KeyStore)
// and OP-level static fields (claims_supported, subject_types_supported, etc.)
// to the discovery document.
//
// Capability declarations (grant_types, scopes, auth_methods, etc.) are
// contributed by their respective endpoint plugins. This ensures the
// discovery document automatically reflects which plugins are enabled:
// if the device plugin is not registered, device_code won't appear in
// grant_types_supported.
package discovery

import (
	"context"
	"slices"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// Plugin is the Discovery contributor plugin.
// It provides algorithm fields (from KeyStore) and OP-level static fields.
// Endpoint URLs and capability declarations are contributed by their
// respective endpoint plugins.
type Plugin struct {
	keyStore storm.KeyStore
	config   Config
}

// Config holds optional overrides for the discovery document.
type Config struct {
	// SubjectTypes overrides subject_types_supported.
	// Default: ["public", "pairwise"]
	SubjectTypes []string

	// ExtraFields are additional key-value pairs merged into cfg.Extra.
	ExtraFields map[string]any
}

// New creates a new Discovery plugin.
// If keyStore is non-nil, the discovery document will include the
// signing algorithms declared by the key store (including GM/T algorithms).
func New(keyStore storm.KeyStore, cfg ...Config) *Plugin {
	var config Config
	if len(cfg) > 0 {
		config = cfg[0]
	}
	return &Plugin{keyStore: keyStore, config: config}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "discovery" }

// Register is a no-op for the Discovery plugin.
func (p *Plugin) Register(r chi.Router) {}

// Contribute populates algorithm fields and OP-level static fields on cfg.
//
// Algorithm fields are derived from KeyStore with RS256 as fallback.
// Capability declarations (grant_types, scopes, auth_methods, etc.) are
// NOT set here — each endpoint plugin contributes its own capabilities.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	// Signing algorithms from KeyStore (for token/response signing)
	signingAlgs := []string{"RS256"}
	if p.keyStore != nil {
		if algs, err := p.keyStore.SignatureAlgorithms(ctx); err == nil && len(algs) > 0 {
			signingAlgs = algs
		}
	}

	// Auth signing algorithms = KeyStore algorithms + HS variants (for client_secret_jwt)
	authSigningAlgs := make([]string, 0, len(signingAlgs)+3)
	authSigningAlgs = append(authSigningAlgs, signingAlgs...)
	for _, hs := range []string{"HS256", "HS384", "HS512"} {
		if !slices.Contains(authSigningAlgs, hs) {
			authSigningAlgs = append(authSigningAlgs, hs)
		}
	}
	slices.Sort(authSigningAlgs)

	// Token/response signing: non-asymmetric only (from KeyStore)
	// Request Object signing: same as OP signing (asymmetric only).
	// "none" is intentionally excluded — unsigned request objects are a
	// security risk and not supported. FAPI profiles require signed objects.
	// HS algorithms are for client_secret_jwt auth, not OP-signed objects.
	cfg.IDTokenSigningAlgValuesSupported = signingAlgs
	cfg.UserinfoSigningAlgValuesSupported = signingAlgs
	cfg.RequestObjectSigningAlgValuesSupported = signingAlgs

	// Client authentication: asymmetric + HS (for client_secret_jwt)
	cfg.TokenEndpointAuthSigningAlgValuesSupported = authSigningAlgs
	cfg.IntrospectionEndpointAuthSigningAlgValuesSupported = authSigningAlgs
	cfg.RevocationEndpointAuthSigningAlgValuesSupported = authSigningAlgs

	// OP-level static fields
	subjectTypes := p.config.SubjectTypes
	if len(subjectTypes) == 0 {
		subjectTypes = []string{"public", "pairwise"}
	}
	cfg.SubjectTypesSupported = subjectTypes
	cfg.ClaimTypesSupported = []string{"normal"}
	cfg.ClaimsSupported = []string{
		"sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr",
		"c_hash", "at_hash", "name", "given_name", "family_name",
		"middle_name", "nickname", "preferred_username", "profile",
		"picture", "website", "email", "email_verified", "gender",
		"birthdate", "zoneinfo", "locale", "phone_number",
		"phone_number_verified", "address", "updated_at",
	}
	cfg.ClaimsParameterSupported = true
	cfg.RequestParameterSupported = true
	cfg.RequestURIParameterSupported = true
	cfg.RequireRequestURIRegistration = false
	cfg.AuthorizationResponseISSParameterSupported = true
	cfg.ScopesSupported = []string{"openid", "profile", "email", "address", "phone", "offline_access"}

	// Extra fields from config
	for k, v := range p.config.ExtraFields {
		cfg.Extra[k] = v
	}
}

func init() {
	storm.RegisterPlugin("discovery", storm.PriorityDiscovery, func(ctx *storm.PluginContext) storm.Plugin {
		var ks storm.KeyStore
		if ks, _ = ctx.Storage.(storm.KeyStore); ks == nil {
			return nil
		}
		return New(ks)
	})
}
