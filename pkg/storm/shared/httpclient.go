package shared

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"syscall"
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

// NewSSRFGuardedClient returns an HTTP client for fetching user-supplied URLs
// (jwks_uri, sector_identifier_uri, request_uri, ...).
//
// On top of pre-flight validation (ValidateRemoteURL), the transport enforces
// IP checks at dial time via net.Dialer.Control, closing the DNS-rebinding
// TOCTOU window: a host that resolves to a public IP during validation but to
// a private IP when the connection is actually established is refused.
//
// Blocked (unless allowPrivate): private, link-local unicast/multicast and
// unspecified IPs. Loopback stays allowed so localhost test setups keep
// working, mirroring ValidateRemoteURL's localhost handling.
func NewSSRFGuardedClient(skipTLSVerify, allowPrivate bool) *http.Client {
	client := NewHTTPClient(skipTLSVerify)
	if allowPrivate {
		return client
	}
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("ssrf guard: invalid address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("ssrf guard: non-IP address %q", host)
			}
			if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return fmt.Errorf("ssrf guard: connection to non-public IP %s refused", ip)
			}
			return nil
		},
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	if skipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	client.Transport = transport
	return client
}

// FetchRemoteURL performs a GET on a user-supplied URL with SSRF protections:
// pre-flight ValidateRemoteURL (unless allowPrivate) and dial-time IP checks.
//
// Callers own the returned response body and must close it.
func FetchRemoteURL(rawURL string, skipTLSVerify, allowPrivate bool) (*http.Response, error) {
	if !allowPrivate {
		if err := ValidateRemoteURL(rawURL); err != nil {
			return nil, fmt.Errorf("url rejected: %w", err)
		}
	}
	client := NewSSRFGuardedClient(skipTLSVerify, allowPrivate)
	// codeql[go/request-forgery] rawURL is user-supplied by protocol design
	// (jwks_uri / sector_identifier_uri / request_uri); it is guarded by the
	// ValidateRemoteURL check above plus dial-time IP validation in
	// NewSSRFGuardedClient. allowPrivate=true is a test-only escape hatch.
	return client.Get(rawURL)
}
