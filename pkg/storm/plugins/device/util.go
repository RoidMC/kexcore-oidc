package device

import (
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
func generateRandomUserCode(length int) string {
	const charset = "BCDFGHJKLMNPQRSTVWXYZ"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
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
