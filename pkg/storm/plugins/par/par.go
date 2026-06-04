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

// Plugin implements the Pushed Authorization Requests endpoint.
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
	Lifetime    time.Duration
}

// New creates a new PAR plugin.
func New(cfg Config) *Plugin {
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

// Name returns the plugin name.
func (p *Plugin) Name() string { return "par" }

// Register installs the POST /par route.
//
// OAuth 2.0 standard endpoint: POST /par (RFC 9126 §3)
func (p *Plugin) Register(r chi.Router) {
	r.Post("/par", p.handle)
}

// Contribute returns the discovery fields for the PAR endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"pushed_authorization_request_endpoint": shared.EndpointURL(ctx, protocol.NewEndpoint("/par")),
	}
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")

	// Authenticate the client
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

	// Parse the authorization request parameters
	authReq := new(protocol.AuthRequest)
	if err := p.decoder.Decode(authReq, r.Form); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error decoding auth request").WithParent(err), nil)
		return
	}

	// Store the pushed authorization request
	requestURI, err := p.store.StorePushedAuthRequest(r.Context(), clientID, authReq, p.lifetime)
	if err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error storing pushed auth request"), nil)
		return
	}

	issuer := shared.IssuerFromContext(r.Context())

	resp := &protocol.PushedAuthResponse{
		RequestURI: requestURI,
		ExpiresIn:  int(p.lifetime.Seconds()),
	}

	// Set the issuer in the response if needed
	_ = issuer

	shared.JSONResponse(w, resp, http.StatusCreated)
}
