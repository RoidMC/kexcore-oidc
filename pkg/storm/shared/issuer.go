// Package shared provides cross-cutting concerns used by all StormEngine plugins.
//
// These are pure functions and middleware that operate at the HTTP layer
// without knowing anything about OIDC protocol semantics.
package shared

import (
	"context"
	"net/http"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
)

type IssuerFromRequest func(*http.Request) string

func ContextWithIssuer(ctx context.Context, issuer string) context.Context {
	return protocol.ContextWithIssuer(ctx, issuer)
}

func IssuerFromContext(ctx context.Context) string {
	return protocol.IssuerFromContext(ctx)
}

// IssuerMiddleware injects the issuer into the request context.
// This is the only middleware that Engine itself needs to install.
func IssuerMiddleware(fn IssuerFromRequest) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := ContextWithIssuer(r.Context(), fn(r))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// StaticIssuer returns an IssuerFromRequest that always returns the given value.
func StaticIssuer(issuer string) IssuerFromRequest {
	return func(_ *http.Request) string {
		return issuer
	}
}

// IssuerFromHost returns an IssuerFromRequest that derives the issuer
// from the request's Host header, using the given path suffix.
func IssuerFromHost(path string) IssuerFromRequest {
	return func(r *http.Request) string {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		if len(path) > 0 && path[0] != '/' {
			path = "/" + path
		}
		return scheme + "://" + r.Host + path
	}
}

// EndpointURL converts a protocol.Endpoint into an absolute URL
// using the issuer from context, applying the same TrimRight logic as IssuerURL.
//
// This allows plugins to declare their paths as *protocol.Endpoint
// and reuse the built-in Absolute() logic instead of hand-joining strings.
//
// Example:
//
//	ep := protocol.NewEndpoint("/authorize")
//	EndpointURL(ctx, ep) → "http://localhost:9998/authorize"
func EndpointURL(ctx context.Context, ep *protocol.Endpoint) string {
	if ep == nil {
		return ""
	}
	return ep.DiscoveryURL(IssuerFromContext(ctx))
}
