// Package jarm implements JWT Secured Authorization Response Mode (RFC 9101).
//
// JARM allows the authorization response to be encoded as a JWT, providing
// integrity protection and authentication of the authorization response.
//
// Supported response modes:
//   - query.jwt: JWT in the query string
//   - fragment.jwt: JWT in the fragment
//   - form_post.jwt: JWT via form post
//
// The JWT contains the standard authorization response claims (code, state, etc.)
// plus standard JWT claims (iss, aud, exp, iat).
package jarm

import (
	"context"
	"fmt"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// DefaultJARMLifetime is the default lifetime for JARM JWTs.
// Per RFC 9101 §5.1, the JWT should have a short expiration.
const DefaultJARMLifetime = 5 * time.Minute

// Plugin implements JARM (JWT Secured Authorization Response Mode).
type Plugin struct {
	keyStore storm.KeyStore
	issuerFn shared.IssuerFromRequest
	lifetime time.Duration
}

// Config holds the dependencies for the JARM plugin.
type Config struct {
	// KeyStore provides signing keys for JWT creation.
	KeyStore storm.KeyStore

	// IssuerFn provides the issuer URL from the request context.
	IssuerFn shared.IssuerFromRequest

	// Lifetime is the JWT expiration duration.
	// Defaults to DefaultJARMLifetime if not set.
	Lifetime time.Duration
}

// New creates a new JARM plugin.
func New(ctx *storm.PluginContext) *Plugin {
	return &Plugin{
		keyStore: ctx.Storage.(storm.KeyStore),
		issuerFn: ctx.IssuerFn,
	}
}

// NewWithConfig creates a new JARM plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	lifetime := cfg.Lifetime
	if lifetime == 0 {
		lifetime = DefaultJARMLifetime
	}
	return &Plugin{
		keyStore: cfg.KeyStore,
		issuerFn: cfg.IssuerFn,
		lifetime: lifetime,
	}
}

// init self-registers the JARM plugin in the global registry.
func init() {
	storm.RegisterPlugin("jarm", storm.PriorityJARM, func(ctx *storm.PluginContext) storm.Plugin {
		return New(ctx)
	})
}

// Category returns CategoryStandard — JARM is an optional extension.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string {
	return []string{"KeyStore"}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "jarm" }

// Register is a no-op for the JARM plugin.
// JARM is integrated via the JARMSigner interface.
func (p *Plugin) Register(r chi.Router) {}

// Contribute returns discovery fields for JARM.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.ResponseModesSupported = append(cfg.ResponseModesSupported,
		"jwt", "query.jwt", "fragment.jwt", "form_post.jwt",
	)
}

// SignAuthResponse implements the JARMSigner interface.
// It creates a signed JWT containing the authorization response parameters.
//
// Per RFC 9101 §5.1, the JWT contains:
//   - iss: the authorization server's issuer URL
//   - aud: the client_id
//   - exp: expiration time
//   - iat: issued at time
//   - All authorization response parameters (code, state, etc.)
//
// The context is used to derive the issuer URL. If no issuer is found
// in the context, an error is returned.
func (p *Plugin) SignAuthResponse(ctx context.Context, params map[string]string, clientID string, signingAlg string) (string, error) {
	// Get issuer from context
	issuer := shared.IssuerFromContext(ctx)
	if issuer == "" {
		return "", fmt.Errorf("jarm: issuer not found in context")
	}

	// Use client's preferred signing algorithm if provided (e.g. PS256 for FAPI).
	// Falls back to the server's default signing key.
	signingKey, err := p.signingKeyForAlg(ctx, signingAlg)
	if err != nil {
		return "", err
	}

	lifetime := p.lifetime
	if lifetime == 0 {
		lifetime = DefaultJARMLifetime
	}

	now := time.Now()
	token := jwt.New()
	token.Set("iss", issuer)
	token.Set("aud", clientID)
	token.Set("iat", now.Unix())
	token.Set("exp", now.Add(lifetime).Unix())

	// Add all authorization response parameters
	for k, v := range params {
		token.Set(k, v)
	}

	alg := determineAlg(signingKey.Algorithm())
	signed, err := jwt.Sign(token, jwt.WithKey(alg, signingKey.Key()))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

// determineAlg maps the key algorithm string to jwa.SignatureAlgorithm.
func determineAlg(alg string) jwa.SignatureAlgorithm {
	if jwaAlg, ok := jwa.LookupSignatureAlgorithm(alg); ok {
		return jwaAlg
	}
	return jwa.RS256()
}

// signingKeyForAlg returns a signing key matching the requested algorithm,
// or falls back to the server's default key.
func (p *Plugin) signingKeyForAlg(ctx context.Context, alg string) (storm.SigningKey, error) {
	if alg != "" {
		if provider, ok := p.keyStore.(storm.SigningKeyByAlgProvider); ok {
			key, err := provider.SigningKeyByAlg(ctx, alg)
			if err == nil {
				return key, nil
			}
			// Fall through to default if the preferred alg is not available.
		}
	}
	return p.keyStore.SigningKey(ctx)
}
