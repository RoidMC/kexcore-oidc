// SPDX-License-Identifier: Apache-2.0
//
//Copyright 2026 RoidMC Studios

// Package logctx provides helpers for storing and retrieving *slog.Logger
// in context.Context, replacing the deprecated github.com/zitadel/logging.
package logctx

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

type ctxKey struct{}

// ToContext stores a *slog.Logger in the context.
func ToContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, logger)
}

// FromContext retrieves a *slog.Logger from the context.
func FromContext(ctx context.Context) (*slog.Logger, bool) {
	logger, ok := ctx.Value(ctxKey{}).(*slog.Logger)
	return logger, ok
}

// MiddlewareOption configures the logging middleware.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	logger *slog.Logger
	idFunc func() slog.Attr
}

// WithLogger sets the base logger for the middleware.
func WithLogger(logger *slog.Logger) MiddlewareOption {
	return func(c *middlewareConfig) {
		c.logger = logger
	}
}

// WithGroup sets a group attribute on the logger for the middleware.
func WithGroup(group string) MiddlewareOption {
	return func(c *middlewareConfig) {
		c.logger = c.logger.With(slog.String("group", group))
	}
}

// WithIDFunc sets a custom function to generate a request ID attribute.
func WithIDFunc(f func() slog.Attr) MiddlewareOption {
	return func(c *middlewareConfig) {
		c.idFunc = f
	}
}

// Middleware returns a chi-compatible middleware that:
//   - Injects the logger into the request context
//   - Generates a request ID (or uses the custom ID function)
//   - Logs each request with method, path, status, and duration
func Middleware(opts ...MiddlewareOption) func(http.Handler) http.Handler {
	cfg := &middlewareConfig{
		logger: slog.Default(),
	}
	for _, o := range opts {
		o(cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			logger := cfg.logger
			if cfg.idFunc != nil {
				logger = logger.With(cfg.idFunc())
			}

			ctx := ToContext(r.Context(), logger)
			r = r.WithContext(ctx)

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				logger.Info("request",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", ww.Status()),
					slog.Duration("duration", time.Since(start)),
				)
			}()

			next.ServeHTTP(ww, r)
		})
	}
}

// HTTPClientOption configures the HTTP client logging transport.
type HTTPClientOption func(*loggingTransport)

type loggingTransport struct {
	transport http.RoundTripper
	logger    *slog.Logger
}

// WithClientGroup sets a group attribute on the logger used for HTTP client logging.
func WithClientGroup(group string) HTTPClientOption {
	return func(lt *loggingTransport) {
		lt.logger = lt.logger.With(slog.String("group", group))
	}
}

// WithClientLogger sets a custom logger for HTTP client logging.
func WithClientLogger(logger *slog.Logger) HTTPClientOption {
	return func(lt *loggingTransport) {
		lt.logger = logger
	}
}

// EnableHTTPClient wraps an http.Client's transport to log request/response via slog.
// Must be called before the client is used; the client must not have a custom Transport.
func EnableHTTPClient(client *http.Client, opts ...HTTPClientOption) {
	lt := &loggingTransport{
		transport: http.DefaultTransport,
		logger:    slog.Default(),
	}
	for _, o := range opts {
		o(lt)
	}
	if client.Transport != nil {
		lt.transport = client.Transport
	}
	client.Transport = lt
}

func (lt *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()

	resp, err := lt.transport.RoundTrip(req)
	if err != nil {
		lt.logger.Error("http client request failed",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.Duration("duration", time.Since(start)),
			slog.Any("error", err),
		)
		return nil, err
	}

	dump, _ := httputil.DumpResponse(resp, true)
	lt.logger.Debug("http client request",
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
		slog.Int("status", resp.StatusCode),
		slog.Duration("duration", time.Since(start)),
		slog.String("response", string(dump)),
	)

	return resp, nil
}
