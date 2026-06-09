package par

import (
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// Plugin implements the Pushed Authorization Requests endpoint (RFC 9126).
type Plugin struct {
	store       storm.PARStore
	clientStore storm.ClientStore
	decoder     *protocol.Decoder
	lifetime    time.Duration
}

// Config holds the dependencies for the PAR plugin.
type Config struct {
	Store       storm.PARStore
	ClientStore storm.ClientStore
	Decoder     *protocol.Decoder
	// Lifetime is the request_uri expiration duration (default: 5m).
	Lifetime time.Duration
}
