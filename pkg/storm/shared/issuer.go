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

// EndpointResolver resolves the absolute URL for a given endpoint.
// It is used by plugins to determine the full URL for their endpoints
// in the discovery document.
type EndpointResolver interface {
	// Resolve returns the absolute URL for the given endpoint.
	// endpointName is a short identifier (e.g., "token", "authorize").
	// defaultPath is the default relative path (e.g., "/token", "/authorize").
	Resolve(ctx context.Context, endpointName, defaultPath string) string
}

// DefaultEndpointResolver is the default implementation that uses the issuer URL
// from the request context to build endpoint URLs.
type DefaultEndpointResolver struct{}

func (r *DefaultEndpointResolver) Resolve(ctx context.Context, endpointName, defaultPath string) string {
	return EndpointURL(ctx, protocol.NewEndpoint(defaultPath))
}

// OverrideEndpointResolver allows customizing specific endpoint URLs
// while falling back to a base resolver for non-overridden endpoints.
//
// Example:
//
//	resolver := &OverrideEndpointResolver{
//	    Base: &DefaultEndpointResolver{},
//	    Overrides: map[string]string{
//	        "token": "https://token-service.example.com/token",
//	    },
//	}
type OverrideEndpointResolver struct {
	Base      EndpointResolver
	Overrides map[string]string
}

func (r *OverrideEndpointResolver) Resolve(ctx context.Context, endpointName, defaultPath string) string {
	if override, ok := r.Overrides[endpointName]; ok {
		return override
	}
	return r.Base.Resolve(ctx, endpointName, defaultPath)
}
