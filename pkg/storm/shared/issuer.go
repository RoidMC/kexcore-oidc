// Package shared provides cross-cutting concerns used by all StormEngine plugins.
//
// These are pure functions and middleware that operate at the HTTP layer
// without knowing anything about OIDC protocol semantics.
package shared

import (
	"context"
	"net/http"
	"strings"
)

// IssuerFromRequest extracts the issuer string from an HTTP request.

// IssuerFromRequest extracts the issuer string from an HTTP request.
// Implementations may use the request host, a forwarded header, or a static value.
type IssuerFromRequest func(*http.Request) string

// IssuerContextKey is the key used to store the issuer in a context.Context.
type issuerContextKey struct{}

// ContextWithIssuer stores the issuer in the context.
func ContextWithIssuer(ctx context.Context, issuer string) context.Context {
	return context.WithValue(ctx, issuerContextKey{}, issuer)
}

// IssuerFromContext retrieves the issuer from the context.
// Returns empty string if not found.
func IssuerFromContext(ctx context.Context) string {
	if s, ok := ctx.Value(issuerContextKey{}).(string); ok {
		return s
	}
	return ""
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

// IssuerURL safely joins an issuer and a URL path, stripping trailing
// slashes from the issuer to avoid double-slashes.
//
// Example:
//
//	IssuerURL(ctx, "/token")    → "http://localhost:9998/token"
//	IssuerURL(ctx, "/register/abc") → "http://localhost:9998/register/abc"
func IssuerURL(ctx context.Context, path string) string {
	issuer := strings.TrimRight(IssuerFromContext(ctx), "/")
	return issuer + path
}
