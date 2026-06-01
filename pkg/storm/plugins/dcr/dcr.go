// Package dcr implements the OAuth 2.0 Dynamic Client Registration plugin.
//
// It handles POST /register (RFC 7591 §3), allowing clients to register
// themselves dynamically with the authorization server.
package dcr

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the Dynamic Client Registration endpoint.
type Plugin struct {
	store storm.DCRStore
}

// Config holds the dependencies for the DCR plugin.
type Config struct {
	Store storm.DCRStore
}

// New creates a new DCR plugin.
func New(cfg Config) *Plugin {
	return &Plugin{
		store: cfg.Store,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "dcr" }

// Register installs the /register routes.
//
// OAuth 2.0 standard endpoint: POST /register (RFC 7591 §3)
// Also supports GET and PUT for reading and updating registrations.
func (p *Plugin) Register(r chi.Router) {
	r.Post("/register", p.handleCreate)
	r.Get("/register/{client_id}", p.handleGet)
	r.Put("/register/{client_id}", p.handleUpdate)
	r.Delete("/register/{client_id}", p.handleDelete)
}

// Contribute returns the discovery fields for the registration endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"registration_endpoint": shared.IssuerURL(ctx, "/register"),
	}
}

func (p *Plugin) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req storm.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error decoding request body").WithParent(err), nil)
		return
	}

	// Generate client credentials
	clientID := generateClientID()
	clientSecret := generateClientSecret()
	accessToken := generateAccessToken()
	uri := shared.IssuerURL(r.Context(), "/register/"+clientID)

	reg, err := p.store.CreateClient(r.Context(), &req, clientID, clientSecret, accessToken, uri)
	if err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error creating client"), nil)
		return
	}

	shared.JSONResponse(w, reg, http.StatusCreated)
}

func (p *Plugin) handleGet(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")

	// Authenticate via registration access token
	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	if token == "" {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("registration access token required"), nil)
		return
	}

	reg, err := p.store.GetClientRegistrationByToken(r.Context(), token)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithParent(err), nil)
		return
	}

	if reg.ClientID != clientID {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("client_id mismatch"), nil)
		return
	}

	shared.JSONResponse(w, reg, http.StatusOK)
}

func (p *Plugin) handleUpdate(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	if token == "" {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("registration access token required"), nil)
		return
	}

	reg, err := p.store.GetClientRegistrationByToken(r.Context(), token)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithParent(err), nil)
		return
	}

	if reg.ClientID != clientID {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("client_id mismatch"), nil)
		return
	}

	var req storm.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error decoding request body").WithParent(err), nil)
		return
	}

	updated, err := p.store.UpdateClientRegistration(r.Context(), clientID, &req)
	if err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error updating client"), nil)
		return
	}

	shared.JSONResponse(w, updated, http.StatusOK)
}

func (p *Plugin) handleDelete(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	if token == "" {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("registration access token required"), nil)
		return
	}

	reg, err := p.store.GetClientRegistrationByToken(r.Context(), token)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithParent(err), nil)
		return
	}

	if reg.ClientID != clientID {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("client_id mismatch"), nil)
		return
	}

	if err := p.store.DeleteClientRegistration(r.Context(), clientID); err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error deleting client"), nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func generateClientID() string     { return "client_" + randomHex(16) }
func generateClientSecret() string { return "secret_" + randomHex(32) }
func generateAccessToken() string  { return "token_" + randomHex(32) }

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
