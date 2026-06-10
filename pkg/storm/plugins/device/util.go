package device

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// generateRandomCode generates a cryptographically random code of the given byte length.
func generateRandomCode(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateRandomUserCode generates a user-friendly code using consonants only
// (to avoid spelling words). RFC 8628 §6.1 recommends this format.
// Returns a code in XXXX-XXXX format for readability.
func generateRandomUserCode(length int) string {
	const charset = "BCDFGHJKLMNPQRSTVWXYZ"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	code := string(b)
	// Insert hyphen in the middle for readability (RFC 8628 §6.1)
	if len(code) >= 4 {
		mid := len(code) / 2
		code = code[:mid] + "-" + code[mid:]
	}
	return code
}

// validateDeviceAuthorizationRequest validates the incoming device authorization request.
// Supports both form-body and HTTP Basic Auth for client credentials (RFC 8628 §3.1).
func validateDeviceAuthorizationRequest(r *http.Request) (clientID, clientSecret string, scopes []string, err error) {
	clientID = r.Form.Get("client_id")
	clientSecret = r.Form.Get("client_secret")
	scopes = r.Form["scope"]

	// Basic Auth takes precedence per RFC 6749 §2.3.1
	if id, secret, ok := r.BasicAuth(); ok {
		if unescaped, e := url.QueryUnescape(id); e == nil {
			clientID = unescaped
		}
		if unescaped, e := url.QueryUnescape(secret); e == nil {
			clientSecret = unescaped
		}
	}

	if clientID == "" {
		return "", "", nil, protocol.ErrInvalidRequest().WithDescription("client_id is required")
	}
	return clientID, clientSecret, scopes, nil
}

// deviceCodeExpired returns true if the device authorization has expired.
func deviceCodeExpired(state *storm.DeviceAuthorizationState) bool {
	return !state.Expires.IsZero() && time.Now().After(state.Expires)
}

// formatScopes formats a scope slice for display.
func formatScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	return strings.Join(scopes, " ")
}

// validateDeviceGrantType checks if the client has the device_code grant type.
func validateDeviceGrantType(client storm.Client) bool {
	type grantTypesProvider interface {
		GrantTypes() []protocol.GrantType
	}
	if gp, ok := client.(grantTypesProvider); ok {
		for _, gt := range gp.GrantTypes() {
			if gt == protocol.GrantTypeDeviceCode {
				return true
			}
		}
		return false
	}
	// Without GrantTypes(), allow by default
	return true

}

// generateUniqueUserCode creates a user_code and ensures it does not collide
// with an existing one in the store. It retries up to maxRetries times.
// Returns the generated code or an error if all retries are exhausted.
func generateUniqueUserCode(ctx context.Context, store storm.DeviceAuthStore, maxRetries int) (string, error) {
	for i := 0; i < maxRetries; i++ {
		code := generateRandomUserCode(8)
		_, err := store.GetDeviceAuthorizationByUserCode(ctx, code)
		if err != nil {
			// Not found = no collision, we can use it
			return code, nil
		}
	}
	return "", protocol.ErrServerError().WithDescription("unable to generate unique user_code")
}

const csrfCookieName = "device_csrf"

// generateCSRFToken creates a random CSRF token.
func generateCSRFToken() string {
	return generateRandomCode(16)
}

// setCSRFCookie writes a signed CSRF token cookie using the configured handler.
func (p *Plugin) setCSRFCookie(w http.ResponseWriter, token string) {
	if p.csrfHandler == nil {
		return
	}
	cookie, err := p.csrfHandler.CreateCookie(csrfCookieName, token)
	if err != nil {
		return
	}
	http.SetCookie(w, cookie)
}

// validateCSRF checks that the request contains a matching signed CSRF cookie and form value.
// Returns true if valid or if CSRF protection is disabled.
func (p *Plugin) validateCSRF(r *http.Request) bool {
	if p.csrfHandler == nil {
		return true // CSRF disabled
	}
	cookieVal, err := p.csrfHandler.CheckCookie(r, csrfCookieName)
	if err != nil {
		return false
	}
	formToken := r.FormValue("csrf_token")
	if formToken == "" {
		return false
	}
	return cookieVal == formToken
}
