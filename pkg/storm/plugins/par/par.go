// Package par implements the OAuth 2.0 Pushed Authorization Requests plugin.
//
// It handles POST /par (RFC 9126 §3), allowing clients to push
// authorization request parameters to the server and receive a
// request_uri in return.
package par

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// NewWithConfig creates a new PAR plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	if cfg.Lifetime == 0 {
		cfg.Lifetime = 5 * time.Minute
	}
	return &Plugin{
		store:       cfg.Store,
		clientStore: cfg.ClientStore,
		decoder:     cfg.Decoder,
		lifetime:    cfg.Lifetime,
	}
}

// init self-registers the PAR plugin in the global registry.
func init() {
	storm.RegisterPlugin("par", storm.PriorityPAR, func(ctx *storm.PluginContext) storm.Plugin {
		parStore, ok := ctx.Storage.(storm.PARStore)
		if !ok {
			return nil
		}
		return NewWithConfig(Config{
			Store:       parStore,
			ClientStore: ctx.Storage.(storm.ClientStore),
			Decoder:     ctx.Decoder,
		})
	})
}

// Category returns CategoryStandard — PAR is optional.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string {
	return []string{"PARStore", "ClientStore"}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "par" }

// OAuth 2.0 standard endpoint: POST /par (RFC 9126 §3)
// Register installs the POST /par route.
func (p *Plugin) Register(r chi.Router) {
	r.Post("/par", p.handle)
}

// Contribute returns the discovery fields for the PAR endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.PushedAuthorizationRequestEndpoint = shared.EndpointURL(ctx, protocol.NewEndpoint("/par"))
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	clientID, clientSecret, err := validatePARRequest(r)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithParent(err), nil)
		return
	}

	if client.AuthMethod() != protocol.AuthMethodNone {
		if err := p.clientStore.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			shared.WriteError(w, r, err, nil)
			return
		}
	}

	authReq := new(protocol.AuthRequest)
	if err := p.decoder.Decode(authReq, r.Form); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error decoding auth request").WithParent(err), nil)
		return
	}

	// RFC 9126 §3: Validate pushed authorization request parameters
	// before storing. This provides fail-fast behavior for clients.
	if err := shared.ValidateAuthRequestParams(client, authReq); err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	requestURI, err := p.store.StorePushedAuthRequest(r.Context(), clientID, authReq, p.lifetime)
	if err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error storing pushed auth request"), nil)
		return
	}

	resp := &protocol.PushedAuthResponse{
		RequestURI: requestURI,
		ExpiresIn:  int(p.lifetime.Seconds()),
	}

	shared.JSONResponse(w, resp, http.StatusCreated)
}
