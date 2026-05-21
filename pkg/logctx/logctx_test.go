// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package logctx

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestToContext_FromContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := ToContext(context.Background(), logger)

	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("expected logger to be found in context")
	}
	if got != logger {
		t.Fatal("logger from context does not match the original")
	}
}

func TestFromContext_Empty(t *testing.T) {
	_, ok := FromContext(context.Background())
	if ok {
		t.Fatal("expected no logger in empty context")
	}
}

func TestToContext_ReturnsNewContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	parent := context.Background()
	child := ToContext(parent, logger)

	// parent context should not contain the logger
	_, ok := FromContext(parent)
	if ok {
		t.Fatal("expected parent context to not contain logger")
	}

	// child context should contain the logger
	_, ok = FromContext(child)
	if !ok {
		t.Fatal("expected child context to contain logger")
	}
}

func TestWithClientLogger(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := &http.Client{}
	EnableHTTPClient(client, WithClientLogger(logger))

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	output := buf.String()
	if !strings.Contains(output, "http client request") {
		t.Fatalf("expected log to contain 'http client request', got: %s", output)
	}
}

func TestEnableHTTPClient_WithClientGroup(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{}
	EnableHTTPClient(client, WithClientLogger(logger), WithClientGroup("test-group"))

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	output := buf.String()
	if !strings.Contains(output, "http client request") {
		t.Fatalf("expected log to contain 'http client request', got: %s", output)
	}
	if !strings.Contains(output, "group=test-group") {
		t.Fatalf("expected log to contain 'group=test-group', got: %s", output)
	}
}

func TestEnableHTTPClient_RequestError(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))

	client := &http.Client{}
	EnableHTTPClient(client, WithClientLogger(logger))

	_, err := client.Get("http://invalid.test.invalid:99999/")
	if err == nil {
		t.Skip("expected error but got none (network may resolve)")
	}

	output := buf.String()
	if !strings.Contains(output, "http client request failed") {
		t.Fatalf("expected log to contain 'http client request failed', got: %s", output)
	}
}

func TestMiddleware_RequestLogging(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mw := Middleware(WithLogger(logger))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	output := buf.String()
	if !strings.Contains(output, "request") {
		t.Fatalf("expected log to contain 'request', got: %s", output)
	}
	if !strings.Contains(output, "method") {
		t.Fatalf("expected log to contain 'method', got: %s", output)
	}
	if !strings.Contains(output, "GET") {
		t.Fatalf("expected log to contain 'GET', got: %s", output)
	}
}

func TestMiddleware_LoggerInContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var ctxLogger *slog.Logger
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		ctxLogger, ok = FromContext(r.Context())
		if !ok {
			t.Error("expected logger in request context")
		}
	})

	mw := Middleware(WithLogger(logger))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	if ctxLogger == nil {
		t.Fatal("expected logger to be set in context")
	}
}

func TestMiddleware_WithGroup(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := Middleware(WithLogger(logger), WithGroup("mygroup"))

	req := httptest.NewRequest(http.MethodGet, "/group-test", nil)
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	output := buf.String()
	if !strings.Contains(output, "group=mygroup") {
		t.Fatalf("expected log to contain 'group=mygroup', got: %s", output)
	}
}

func TestMiddleware_WithIDFunc(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var counter int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := Middleware(
		WithLogger(logger),
		WithIDFunc(func() slog.Attr {
			counter++
			return slog.Int64("req_id", counter)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/id-test", nil)
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	output := buf.String()
	if !strings.Contains(output, "req_id=1") {
		t.Fatalf("expected log to contain 'req_id=1', got: %s", output)
	}
}

func TestMiddleware_StatusCode(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mw := Middleware(WithLogger(logger))

	req := httptest.NewRequest(http.MethodGet, "/notfound", nil)
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	output := buf.String()
	if !strings.Contains(output, "status=404") {
		t.Fatalf("expected log to contain 'status=404', got: %s", output)
	}
}

func TestEnableHTTPClient_PreservesExistingTransport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{}
	EnableHTTPClient(client, WithClientLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	lt, ok := client.Transport.(*loggingTransport)
	if !ok {
		t.Fatal("expected transport to be *loggingTransport")
	}
	if lt.transport != http.DefaultTransport {
		t.Fatal("expected underlying transport to be http.DefaultTransport")
	}
}
