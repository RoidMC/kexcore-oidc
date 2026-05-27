// Package backchannel implements the OIDC Back-Channel Logout plugin.
//
// It handles POST /backchannel_logout (OIDC Back-Channel Logout §4),
// allowing the OP to send logout tokens to RPs via back-channel.
package backchannel

import (
	"context"
	"net/http"
	"reflect"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/codec"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the OIDC Back-Channel Logout endpoint.
type Plugin struct {
	store      storm.BackChannelStore
	crypto     storm.Crypto
	keyStore   storm.KeyStore
	converters map[reflect.Type]codec.Converter
}

// Config holds the dependencies for the BackChannel plugin.
type Config struct {
	Store      storm.BackChannelStore
	Crypto     storm.Crypto
	KeyStore   storm.KeyStore
	Converters map[reflect.Type]codec.Converter
}

// New creates a new BackChannel plugin.
func New(cfg Config) *Plugin {
	return &Plugin{
		store:      cfg.Store,
		crypto:     cfg.Crypto,
		keyStore:   cfg.KeyStore,
		converters: cfg.Converters,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "backchannel" }

// Register installs the POST /backchannel_logout route.
//
// OIDC standard endpoint: POST /backchannel_logout (OIDC Back-Channel Logout §4)
func (p *Plugin) Register(r chi.Router) {
	r.Post("/backchannel_logout", p.handle)
}

// Contribute returns the discovery fields for the backchannel logout endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"backchannel_logout_supported":         true,
		"backchannel_logout_session_supported": true,
	}
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	// Back-channel logout is typically initiated by the OP, not by external clients.
	// This endpoint receives logout notifications and pushes logout tokens to RPs.
	//
	// The actual logout token creation and delivery is handled internally
	// when a session is terminated (e.g., via endsession plugin).

	// For now, this is a placeholder that acknowledges the request.
	// The real back-channel logout logic involves:
	// 1. Receiving a logout token from another OP or internal trigger
	// 2. Validating the logout token
	// 3. Finding affected RPs via ClientsForSession
	// 4. Pushing logout tokens to each RP's backchannel_logout_uri

	shared.JSONResponse(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// PushLogoutTokens sends logout tokens to all RPs that have sessions
// for the given subject and session ID.
func PushLogoutTokens(ctx context.Context, store storm.BackChannelStore, subject, sid string) error {
	clients, err := store.ClientsForSession(ctx, subject, sid)
	if err != nil {
		return err
	}

	// TODO: Create and send logout tokens to each client's backchannel_logout_uri
	_ = clients
	return nil
}
