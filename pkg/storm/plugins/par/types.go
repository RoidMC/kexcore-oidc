package par

import (
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

// Plugin implements the Pushed Authorization Requests endpoint (RFC 9126).
type Plugin struct {
	store             storm.PARStore
	clientStore       storm.ClientStore
	decoder           *protocol.Decoder
	lifetime          time.Duration
	skipTLSCertVerify bool
	allowPrivateIPs   bool
	endpointResolver  shared.EndpointResolver // endpoint URL resolver (optional)
}

// Config holds the dependencies for the PAR plugin.
type Config struct {
	Store       storm.PARStore
	ClientStore storm.ClientStore
	Decoder     *protocol.Decoder
	// Lifetime is the request_uri expiration duration (default: 5m).
	Lifetime time.Duration
	// SkipTLSCertVerify disables TLS certificate verification on outbound HTTP (testing only).
	SkipTLSCertVerify bool
	// AllowPrivateIPs disables SSRF protection for outbound HTTP (testing only).
	AllowPrivateIPs bool
	// EndpointResolver is an optional endpoint URL resolver for customizing endpoint URLs.
	EndpointResolver shared.EndpointResolver
}
