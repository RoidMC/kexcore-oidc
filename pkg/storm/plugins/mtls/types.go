package mtls

import (
	"context"
	"crypto/x509"
)

// Plugin implements mTLS client authentication and certificate-bound tokens.
type Plugin struct{}

// NewWithConfig creates a new mTLS plugin.
func NewWithConfig() *Plugin {
	return &Plugin{}
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
