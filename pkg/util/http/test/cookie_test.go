// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/securecookie"
	httphelper "github.com/roidmc/kexcore-oidc/pkg/util/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testHashKey    = []byte("0123456789abcdef0123456789abcdef") // 32 bytes for SHA256
	testEncryptKey = []byte("0123456789abcdef0123456789abcdef") // 32 bytes for AES-256
)

func TestNewCookieHandler(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey)
	assert.NotNil(t, handler)
}

func TestCookieHandler_SetAndGetCookie(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey)
	cookieName := "test_cookie"
	cookieValue := "test_value"

	// Create a test server that sets a cookie
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			err := handler.SetCookie(w, cookieName, cookieValue)
			assert.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		case "/get":
			val, err := handler.CheckCookie(r, cookieName)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write([]byte(val))
		}
	}))
	defer server.Close()

	// Set cookie
	resp, err := http.Get(server.URL + "/set")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Get cookie from response
	cookies := resp.Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, cookieName, cookies[0].Name)

	// Use cookie in next request
	req, err := http.NewRequest(http.MethodGet, server.URL+"/get", nil)
	require.NoError(t, err)
	req.AddCookie(cookies[0])

	client := &http.Client{}
	resp2, err := client.Do(req)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestCookieHandler_CheckCookie_MissingCookie(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := handler.CheckCookie(req, "nonexistent")
	assert.Error(t, err)
}

func TestCookieHandler_CheckCookie_InvalidValue(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "test",
		Value: "invalid-encoded-value",
	})

	_, err := handler.CheckCookie(req, "test")
	assert.Error(t, err)
}

func TestCookieHandler_CheckQueryCookie(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey)
	cookieName := "state"
	cookieValue := "random-state-value"

	// Create encoded value
	cookie, err := handler.CreateCookie(cookieName, cookieValue)
	require.NoError(t, err)

	// Test matching query and cookie
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+cookieValue, nil)
	req.AddCookie(cookie)

	val, err := handler.CheckQueryCookie(req, cookieName)
	assert.NoError(t, err)
	assert.Equal(t, cookieValue, val)
}

func TestCookieHandler_CheckQueryCookie_Mismatch(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey)
	cookieName := "state"
	cookieValue := "random-state-value"

	// Create encoded value
	cookie, err := handler.CreateCookie(cookieName, cookieValue)
	require.NoError(t, err)

	// Test mismatched query and cookie
	req := httptest.NewRequest(http.MethodGet, "/callback?state=wrong-value", nil)
	req.AddCookie(cookie)

	_, err = handler.CheckQueryCookie(req, cookieName)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not compare")
}

func TestCookieHandler_CreateCookie(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey)

	cookie, err := handler.CreateCookie("test", "value")
	require.NoError(t, err)
	assert.NotNil(t, cookie)
	assert.Equal(t, "test", cookie.Name)
	assert.NotEmpty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.Equal(t, "/", cookie.Path)
}

func TestCookieHandler_DeleteCookie(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey)

	w := httptest.NewRecorder()
	handler.DeleteCookie(w, "test")

	resp := w.Result()
	cookies := resp.Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "test", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.Equal(t, -1, cookies[0].MaxAge)
	assert.True(t, cookies[0].HttpOnly)
}

func TestCookieHandler_WithDomain(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey,
		httphelper.WithDomain("example.com"))

	cookie, err := handler.CreateCookie("test", "value")
	require.NoError(t, err)
	assert.Equal(t, "example.com", cookie.Domain)
}

func TestCookieHandler_WithPath(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey,
		httphelper.WithPath("/api"))

	cookie, err := handler.CreateCookie("test", "value")
	require.NoError(t, err)
	assert.Equal(t, "/api", cookie.Path)
}

func TestCookieHandler_WithMaxAge(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey,
		httphelper.WithMaxAge(3600))

	cookie, err := handler.CreateCookie("test", "value")
	require.NoError(t, err)
	assert.Equal(t, 3600, cookie.MaxAge)
}

func TestCookieHandler_WithUnsecure(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey,
		httphelper.WithUnsecure())

	cookie, err := handler.CreateCookie("test", "value")
	require.NoError(t, err)
	assert.False(t, cookie.Secure)
}

func TestCookieHandler_WithSameSite(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey,
		httphelper.WithSameSite(http.SameSiteStrictMode))

	cookie, err := handler.CreateCookie("test", "value")
	require.NoError(t, err)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
}

func TestCookieHandler_IsRequestAware(t *testing.T) {
	// Regular cookie handler
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey)
	assert.False(t, handler.IsRequestAware())

	// Request-aware cookie handler
	raHandler := httphelper.NewRequestAwareCookieHandler(func(r *http.Request) (*securecookie.SecureCookie, error) {
		return securecookie.New(testHashKey, testEncryptKey), nil
	})
	assert.True(t, raHandler.IsRequestAware())
}

func TestCookieHandler_SetCookie_RequestAwareError(t *testing.T) {
	handler := httphelper.NewRequestAwareCookieHandler(func(r *http.Request) (*securecookie.SecureCookie, error) {
		return securecookie.New(testHashKey, testEncryptKey), nil
	})

	w := httptest.NewRecorder()
	err := handler.SetCookie(w, "test", "value")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request aware")
}

func TestCookieHandler_SetRequestAwareCookie_NotRequestAwareError(t *testing.T) {
	handler := httphelper.NewCookieHandler(testHashKey, testEncryptKey)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	err := handler.SetRequestAwareCookie(req, w, "test", "value")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not request aware")
}

func TestCookieHandler_RequestAwareCookie(t *testing.T) {
	cookieName := "test_cookie"
	cookieValue := "test_value"

	handler := httphelper.NewRequestAwareCookieHandler(func(r *http.Request) (*securecookie.SecureCookie, error) {
		return securecookie.New(testHashKey, testEncryptKey), nil
	})

	// Test SetRequestAwareCookie
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	err := handler.SetRequestAwareCookie(req, w, cookieName, cookieValue)
	assert.NoError(t, err)

	// Get cookie from response
	resp := w.Result()
	cookies := resp.Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, cookieName, cookies[0].Name)

	// Test CheckCookie with request-aware handler
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.AddCookie(cookies[0])

	val, err := handler.CheckCookie(req2, cookieName)
	assert.NoError(t, err)
	assert.Equal(t, cookieValue, val)
}
