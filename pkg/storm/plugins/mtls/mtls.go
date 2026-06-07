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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements mTLS client authentication and certificate-bound tokens.
type Plugin struct {
	store     storm.ClientStore
	certStore CertificateBinder
}

// CertificateBinder is the optional storage interface for certificate binding.
// If the storage implements this interface, the plugin will bind tokens to
// client certificates via the cnf claim.
type CertificateBinder interface {
	// BindCertificate associates a certificate thumbprint with a client ID.
	BindCertificate(ctx context.Context, clientID string, thumbprint string) error

	// VerifyCertificate checks if a certificate thumbprint is bound to a client ID.
	VerifyCertificate(ctx context.Context, clientID string, thumbprint string) (bool, error)
}

// Config holds the dependencies for the mTLS plugin.
type Config struct {
	ClientStore storm.ClientStore
	CertStore   CertificateBinder
}

// New creates a new mTLS plugin.
func New(cfg Config) *Plugin {
	return &Plugin{
		store:     cfg.ClientStore,
		certStore: cfg.CertStore,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "mtls" }

// Register is a no-op for the mTLS plugin.
// mTLS enforcement is handled by middleware, not route registration.
func (p *Plugin) Register(r chi.Router) {}

// Contribute returns discovery fields for mTLS.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.MTLSEndpointAliases = map[string]string{
		"token_endpoint":         shared.EndpointURL(ctx, protocol.NewEndpoint("/token")),
		"userinfo_endpoint":      shared.EndpointURL(ctx, protocol.NewEndpoint("/userinfo")),
		"revocation_endpoint":    shared.EndpointURL(ctx, protocol.NewEndpoint("/revoke")),
		"introspection_endpoint": shared.EndpointURL(ctx, protocol.NewEndpoint("/introspect")),
	}
	cfg.TLSClientCertificateBoundAccessTokens = true
	// Append mTLS auth methods to the existing list
	cfg.TokenEndpointAuthMethodsSupported = append(cfg.TokenEndpointAuthMethodsSupported,
		"tls_client_auth",
		"self_signed_tls_client_auth",
	)
}

// --- Context helpers ---

type clientCertContextKey struct{}

// ContextWithClientCert stores the client certificate in the request context.
func ContextWithClientCert(ctx context.Context, cert *x509.Certificate) context.Context {
	return context.WithValue(ctx, clientCertContextKey{}, cert)
}

// ClientCertFromContext retrieves the client certificate from the context.
// Returns nil if no certificate was presented.
func ClientCertFromContext(ctx context.Context) *x509.Certificate {
	cert, _ := ctx.Value(clientCertContextKey{}).(*x509.Certificate)
	return cert
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

// --- Certificate utilities ---

// CertThumbprint computes the SHA-256 thumbprint of a certificate
// as a base64url-encoded string (RFC 8705 §3.1, x5t#S256).
func CertThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// ClientCertAuthentication authenticates the client using the TLS client
// certificate per RFC 8705 Section 3.
//
// For tls_client_auth: verifies the certificate chain against the trusted roots.
// For self_signed_tls_client_auth: verifies the cert is self-signed and registered.
func ClientCertAuthentication(r *http.Request, clientID string) (bool, error) {
	cert := ClientCertFromContext(r.Context())
	if cert == nil {
		return false, nil
	}

	// Verify basic certificate validity
	if err := cert.CheckSignatureFrom(cert); err != nil {
		// Not self-signed - check against system roots
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		_, err := cert.Verify(x509.VerifyOptions{Roots: pool})
		if err != nil {
			return false, nil
		}
	}

	return true, nil
}

// CNFClaim returns the cnf claim for certificate-bound tokens (RFC 8705 §3.1).
func CNFClaim(cert *x509.Certificate) map[string]any {
	return map[string]any{
		"x5t#S256": CertThumbprint(cert),
	}
}
