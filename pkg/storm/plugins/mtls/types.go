// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package mtls

import (
	"context"
	"crypto/x509"

	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements mTLS client authentication and certificate-bound tokens.
type Plugin struct{}

// NewWithConfig creates a new mTLS plugin.
func NewWithConfig() *Plugin {
	return &Plugin{}
}

// --- Context helpers ---
// Delegate to shared context helpers for cross-package access.

// ContextWithClientCert stores the client certificate in the request context.
func ContextWithClientCert(ctx context.Context, cert *x509.Certificate) context.Context {
	return shared.ContextWithClientCert(ctx, cert)
}

// ClientCertFromContext retrieves the client certificate from the context.
// Returns nil if no certificate was presented.
func ClientCertFromContext(ctx context.Context) *x509.Certificate {
	return shared.ClientCertFromContext(ctx)
}
