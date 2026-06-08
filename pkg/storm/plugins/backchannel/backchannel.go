// Package backchannel implements the OIDC Back-Channel Logout plugin.
//
// It handles POST /backchannel_logout (OIDC Back-Channel Logout §4),
// allowing the OP to send logout tokens to RPs via back-channel.
package backchannel

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the OIDC Back-Channel Logout endpoint.
type Plugin struct {
	store    storm.BackChannelStore
	keyStore storm.KeyStore
}

// New creates a new BackChannel plugin from a PluginContext.
func New(ctx *storm.PluginContext) *Plugin {
	return &Plugin{
		store:    ctx.Storage.(storm.BackChannelStore),
		keyStore: ctx.Storage.(storm.KeyStore),
	}
}

// init self-registers the backchannel plugin in the global registry.
func init() {
	storm.RegisterPlugin("backchannel", storm.PriorityBackChannel, func(ctx *storm.PluginContext) storm.Plugin {
		return New(ctx)
	})
}

// Category returns CategoryStandard — backchannel is optional but enabled by default.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string {
	return []string{"BackChannelStore", "KeyStore"}
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
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.BackChannelLogoutEndpoint = shared.EndpointURL(ctx, protocol.NewEndpoint("/backchannel_logout"))
	cfg.BackChannelLogoutSupported = true
	cfg.BackChannelLogoutSessionSupported = true
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	// Per OIDC Back-Channel Logout §2.8, the endpoint responds with 200 OK.
	// The actual back-channel logout is OP-initiated (push model).
	// This endpoint is for receiving logout tokens from other OPs or internal triggers.

	shared.JSONResponse(w, nil, http.StatusOK)
}

// PushLogoutTokens sends logout tokens to all RPs that have sessions
// for the given subject and session ID (OIDC Back-Channel Logout §2.5).
//
// This is the main entry point for triggering back-channel logout.
// Call this when a session is terminated (e.g., from endsession plugin).
func PushLogoutTokens(ctx context.Context, store storm.BackChannelStore, issuer string, signingKey storm.SigningKey, subject, sid string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	clients, err := store.ClientsForSession(ctx, subject, sid)
	if err != nil {
		return err
	}

	for _, client := range clients {
		bc, ok := client.(BackChannelLogoutClient)
		if !ok {
			continue
		}
		uri := bc.BackChannelLogoutURI()
		if uri == "" {
			continue
		}

		logoutToken, err := createLogoutToken(issuer, subject, client.GetID(), sid, signingKey)
		if err != nil {
			logger.Error("failed to create logout token",
				slog.String("client_id", client.GetID()),
				slog.String("subject", subject),
				slog.String("sid", sid),
				slog.Any("error", err),
			)
			continue
		}

		go sendLogoutToken(uri, logoutToken, logger)
	}

	return nil
}
