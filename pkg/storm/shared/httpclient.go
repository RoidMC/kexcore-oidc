package shared

import (
	"crypto/tls"
	"net/http"
	"time"
)

// NewHTTPClient creates an HTTP client for outbound requests (JWKS fetches,
// request_uri, backchannel_logout, etc.).
//
// Options (all disabled by default):
//   - skipTLSVerify: skips TLS certificate verification. Use ONLY for testing
//     with self-signed certificates. NEVER enable in production.
func NewHTTPClient(skipTLSVerify bool) *http.Client {
	if skipTLSVerify {
		return &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}
	}
	return &http.Client{Timeout: 10 * time.Second}
}
