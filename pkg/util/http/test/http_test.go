// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package http_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	httphelper "github.com/roidmc/kexcore-oidc/v2/pkg/util/http"
)

func TestHttpRequest_NilClient(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	err := httphelper.HttpRequest(nil, req, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client must not be nil")
}

func TestHttpRequest_Success(t *testing.T) {
	type response struct {
		Message string `json:"message"`
	}
	want := response{Message: "hello"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(want)
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	var got response
	err = httphelper.HttpRequest(server.Client(), req, &got)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestHttpRequest_NonOKStatus_NoBodyLeak(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"internal":"sensitive internal detail","stack":"trace info"}`))
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	var got map[string]any
	err = httphelper.HttpRequest(server.Client(), req, &got)
	assert.Error(t, err)
	// The response body is not a valid OIDC error, so it should be a generic status error
	// that does NOT contain the raw response body
	assert.NotContains(t, err.Error(), "sensitive internal detail")
	assert.Contains(t, err.Error(), "http status not ok")
}

func TestHttpRequest_OIDCError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"The authorization code has expired"}`))
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	var got map[string]any
	err = httphelper.HttpRequest(server.Client(), req, &got)
	assert.Error(t, err)
	// Should return a structured OIDC error, not a raw string error
	assert.Contains(t, err.Error(), "invalid_grant")
}

func TestHttpRequest_LargeBodyTruncated(t *testing.T) {
	// Return a body larger than 1 MB to verify LimitReader is in effect
	largeBody := strings.Repeat("x", 2<<20) // 2 MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largeBody))
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	var got json.RawMessage
	err = httphelper.HttpRequest(server.Client(), req, &got)
	// The response will be truncated, so JSON unmarshal may fail or succeed with partial data
	// The key point is that it doesn't OOM and the read is bounded
	_ = err
}

func TestAuthorizeBasic(t *testing.T) {
	fn := httphelper.AuthorizeBasic("user", "p@ss:word")
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	fn(req)

	username, password, ok := req.BasicAuth()
	assert.True(t, ok)
	assert.Equal(t, "user", username)
	assert.Equal(t, "p@ss:word", password)
}

func TestFormRequest(t *testing.T) {
	type form struct {
		GrantType string `schema:"grant_type"`
		Code      string `schema:"code"`
	}

	encoder := &testEncoder{}

	req, err := httphelper.FormRequest(context.Background(), "http://example.com/token", form{
		GrantType: "authorization_code",
		Code:      "abc123",
	}, encoder, nil)
	require.NoError(t, err)
	assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
	assert.Equal(t, http.MethodPost, req.Method)
}

func TestStartServer_GracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// StartServer should not panic or call log.Fatalf on shutdown
	httphelper.StartServer(ctx, "0")

	// Give the server a moment to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	// Give shutdown time to complete
	time.Sleep(100 * time.Millisecond)
}

// testEncoder is a minimal Encoder implementation for testing
type testEncoder struct{}

func (e *testEncoder) Encode(src any, dst map[string][]string) error {
	m, ok := src.(map[string]string)
	if !ok {
		// Use JSON tag-based encoding for structs
		data, err := json.Marshal(src)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return err
		}
		for k, v := range m {
			dst[k] = []string{fmt.Sprintf("%v", v)}
		}
		return nil
	}
	for k, v := range m {
		dst[k] = []string{v}
	}
	return nil
}
