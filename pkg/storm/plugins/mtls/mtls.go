// Package mtls implements OAuth 2.0 Mutual-TLS client authentication
// and certificate-bound access tokens (RFC 8705).
//
// It provides:
//   - Middleware to extract the client TLS certificate from the request
//   - Client authentication using mTLS (Section 3)
//   - Certificate-bound access tokens (Section 3.1, cnf.x5t#S256)
//   - Introspection binding verification (Section 6)
package mtls

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// init self-registers the mTLS plugin in the global registry.
func init() {
	storm.RegisterPlugin("mtls", storm.PriorityMTLS, func(ctx *storm.PluginContext) storm.Plugin {
		return NewWithConfig()
	})
}

// Category returns CategoryStandard — mTLS is optional.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

// Requires returns no storage dependencies.
func (p *Plugin) Requires() []string { return nil }

// Name returns the plugin name.
func (p *Plugin) Name() string { return "mtls" }

// Register is a no-op for the mTLS plugin.
// mTLS enforcement is handled by middleware, not route registration.
func (p *Plugin) Register(r chi.Router) {}

// Middleware implements storm.MiddlewareProvider. It extracts the client
// TLS certificate from the connection and stores it in the request context.
func (p *Plugin) Middleware(next http.Handler) http.Handler {
	return ClientCertMiddleware(next)
}

// Contribute returns discovery fields for mTLS.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.MTLSEndpointAliases = map[string]string{
		"token_endpoint":         shared.EndpointURL(ctx, protocol.NewEndpoint("/token")),
		"userinfo_endpoint":      shared.EndpointURL(ctx, protocol.NewEndpoint("/userinfo")),
		"revocation_endpoint":    shared.EndpointURL(ctx, protocol.NewEndpoint("/revoke")),
		"introspection_endpoint": shared.EndpointURL(ctx, protocol.NewEndpoint("/introspect")),
	}
	// Only add aliases for endpoints that other plugins have actually registered.
	aliases := cfg.MTLSEndpointAliases.(map[string]string)
	if cfg.RegistrationEndpoint != "" {
		aliases["registration_endpoint"] = cfg.RegistrationEndpoint
	}
	if cfg.DeviceAuthorizationEndpoint != "" {
		aliases["device_authorization_endpoint"] = cfg.DeviceAuthorizationEndpoint
	}
	if cfg.PushedAuthorizationRequestEndpoint != "" {
		aliases["pushed_authorization_request_endpoint"] = cfg.PushedAuthorizationRequestEndpoint
	}
	if cfg.BackchannelAuthenticationEndpoint != "" {
		aliases["backchannel_authentication_endpoint"] = cfg.BackchannelAuthenticationEndpoint
	}
	cfg.TLSClientCertificateBoundAccessTokens = true
	cfg.TokenEndpointAuthMethodsSupported = append(cfg.TokenEndpointAuthMethodsSupported,
		string(protocol.AuthMethodTLSClientAuth),
		string(protocol.AuthMethodSelfSignedTLSAuth),
	)
	// Also add mTLS auth methods to introspection and revocation endpoints
	// if those plugins have registered their endpoints.
	if cfg.IntrospectionEndpoint != "" {
		cfg.IntrospectionEndpointAuthMethodsSupported = append(cfg.IntrospectionEndpointAuthMethodsSupported,
			string(protocol.AuthMethodTLSClientAuth),
			string(protocol.AuthMethodSelfSignedTLSAuth),
		)
	}
	if cfg.RevocationEndpoint != "" {
		cfg.RevocationEndpointAuthMethodsSupported = append(cfg.RevocationEndpointAuthMethodsSupported,
			string(protocol.AuthMethodTLSClientAuth),
			string(protocol.AuthMethodSelfSignedTLSAuth),
		)
	}
}

// --- Middleware ---

// ClientCertMiddleware extracts the client certificate from the TLS connection
// and stores it in the request context.
//
// This middleware should be applied to all routes that need to check
// client certificates. It does NOT enforce that a certificate is present;
// individual handlers decide whether to require one.
func ClientCertMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			ctx := ContextWithClientCert(r.Context(), r.TLS.PeerCertificates[0])
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// RequireClientCertMiddleware rejects requests without a valid client certificate.
func RequireClientCertMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, `{"error":"invalid_client","error_description":"client certificate required"}`, http.StatusUnauthorized)
			return
		}
		ctx := ContextWithClientCert(r.Context(), r.TLS.PeerCertificates[0])
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
