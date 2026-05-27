package shared

import (
	"errors"
	"net/http"

	"github.com/gorilla/securecookie"
)

// CookieHandler provides secure cookie encoding/decoding for OIDC sessions.
// It wraps gorilla/securecookie with OIDC-appropriate defaults.
type CookieHandler struct {
	securecookie     *securecookie.SecureCookie
	secureCookieFunc func(r *http.Request) (*securecookie.SecureCookie, error)
	secureOnly       bool
	sameSite         http.SameSite
	maxAge           int
	domain           string
	path             string
}

// NewCookieHandler creates a CookieHandler with the given keys.
func NewCookieHandler(hashKey, encryptKey []byte, opts ...CookieHandlerOpt) *CookieHandler {
	c := &CookieHandler{
		securecookie: securecookie.New(hashKey, encryptKey),
		secureOnly:   true,
		sameSite:     http.SameSiteLaxMode,
		path:         "/",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewRequestAwareCookieHandler creates a CookieHandler that selects
// a SecureCookie instance per-request (e.g., for multi-tenant setups).
func NewRequestAwareCookieHandler(fn func(r *http.Request) (*securecookie.SecureCookie, error), opts ...CookieHandlerOpt) *CookieHandler {
	c := &CookieHandler{
		secureCookieFunc: fn,
		secureOnly:       true,
		sameSite:         http.SameSiteLaxMode,
		path:             "/",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// CookieHandlerOpt configures a CookieHandler.
type CookieHandlerOpt func(*CookieHandler)

// WithUnsecure disables the Secure flag on cookies.
func WithUnsecure() CookieHandlerOpt {
	return func(c *CookieHandler) { c.secureOnly = false }
}

// WithSameSite sets the SameSite attribute.
func WithSameSite(sameSite http.SameSite) CookieHandlerOpt {
	return func(c *CookieHandler) { c.sameSite = sameSite }
}

// WithMaxAge sets the MaxAge attribute.
func WithMaxAge(maxAge int) CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.maxAge = maxAge
		if !c.IsRequestAware() {
			c.securecookie.MaxAge(maxAge)
		}
	}
}

// WithDomain sets the Domain attribute.
func WithDomain(domain string) CookieHandlerOpt {
	return func(c *CookieHandler) { c.domain = domain }
}

// WithPath sets the Path attribute.
func WithPath(path string) CookieHandlerOpt {
	return func(c *CookieHandler) { c.path = path }
}

// CheckCookie decodes a named cookie from the request.
func (c *CookieHandler) CheckCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	sc := c.securecookie
	if c.IsRequestAware() {
		sc, err = c.secureCookieFunc(r)
		if err != nil {
			return "", err
		}
	}
	var value string
	if err := sc.Decode(name, cookie.Value, &value); err != nil {
		return "", err
	}
	return value, nil
}

// CheckQueryCookie decodes a cookie and verifies it matches the query parameter.
func (c *CookieHandler) CheckQueryCookie(r *http.Request, name string) (string, error) {
	value, err := c.CheckCookie(r, name)
	if err != nil {
		return "", err
	}
	if value != r.FormValue(name) {
		return "", errors.New(name + " does not compare")
	}
	return value, nil
}

// CreateCookie creates an encoded http.Cookie.
func (c *CookieHandler) CreateCookie(name, value string) (*http.Cookie, error) {
	encoded, err := c.securecookie.Encode(name, value)
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     name,
		Value:    encoded,
		Domain:   c.domain,
		Path:     c.path,
		MaxAge:   c.maxAge,
		HttpOnly: true,
		Secure:   c.secureOnly,
		SameSite: c.sameSite,
	}, nil
}

// SetCookie encodes and sets a cookie on the response.
func (c *CookieHandler) SetCookie(w http.ResponseWriter, name, value string) error {
	if c.IsRequestAware() {
		return errors.New("cookie handler is request aware")
	}
	cookie, err := c.CreateCookie(name, value)
	if err != nil {
		return err
	}
	http.SetCookie(w, cookie)
	return nil
}

// SetRequestAwareCookie encodes and sets a cookie using the per-request SecureCookie.
func (c *CookieHandler) SetRequestAwareCookie(r *http.Request, w http.ResponseWriter, name, value string) error {
	if !c.IsRequestAware() {
		return errors.New("cookie handler is not request aware")
	}
	sc, err := c.secureCookieFunc(r)
	if err != nil {
		return err
	}
	encoded, err := sc.Encode(name, value)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    encoded,
		Domain:   c.domain,
		Path:     c.path,
		MaxAge:   c.maxAge,
		HttpOnly: true,
		Secure:   c.secureOnly,
		SameSite: c.sameSite,
	})
	return nil
}

// DeleteCookie removes a cookie by setting MaxAge to -1.
func (c *CookieHandler) DeleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Domain:   c.domain,
		Path:     c.path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secureOnly,
		SameSite: c.sameSite,
	})
}

// IsRequestAware returns true if this handler uses per-request SecureCookie selection.
func (c *CookieHandler) IsRequestAware() bool {
	return c.secureCookieFunc != nil
}
