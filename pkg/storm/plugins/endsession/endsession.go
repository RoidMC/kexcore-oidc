// Package endsession implements the OIDC RP-Initiated Logout endpoint plugin.
//
// It handles GET/POST /end_session (OIDC Session Management §5),
// allowing relying parties to initiate logout of the end-user.
package endsession

import (
	"context"
	"net/http"
	"reflect"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/codec"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the OIDC End Session endpoint.
type Plugin struct {
	store            storm.SessionStore
	clientStore      storm.ClientStore
	defaultLogoutURI string
	converters       map[reflect.Type]codec.Converter
}

// Config holds the dependencies for the EndSession plugin.
type Config struct {
	Store            storm.SessionStore
	ClientStore      storm.ClientStore
	DefaultLogoutURI string
	Converters       map[reflect.Type]codec.Converter
}

// New creates a new EndSession plugin.
func New(cfg Config) *Plugin {
	return &Plugin{
		store:            cfg.Store,
		clientStore:      cfg.ClientStore,
		defaultLogoutURI: cfg.DefaultLogoutURI,
		converters:       cfg.Converters,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "endsession" }

// Register installs the /end_session route.
//
// OIDC standard endpoint: GET/POST /end_session (OIDC Session Management §5)
func (p *Plugin) Register(r chi.Router) {
	r.Get("/end_session", p.handle)
	r.Post("/end_session", p.handle)
}

// Contribute returns the discovery fields for the end_session endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"end_session_endpoint": shared.IssuerFromContext(ctx) + "/end_session",
	}
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	req, err := parseEndSessionRequest(r.Form, p.converters)
	if err != nil {
		shared.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err), nil)
		return
	}

	session, err := validateEndSessionRequest(r.Context(), req)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	// Terminate the session
	if err := p.store.TerminateSession(r.Context(), session.UserID, session.ClientID); err != nil {
		shared.WriteError(w, r, oidc.DefaultToServerError(err, "error terminating session"), nil)
		return
	}

	// Redirect to the post-logout URI or default
	redirectURI := session.RedirectURI
	if redirectURI == "" {
		redirectURI = p.defaultLogoutURI
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func parseEndSessionRequest(form map[string][]string, converters map[reflect.Type]codec.Converter) (*oidc.EndSessionRequest, error) {
	req := new(oidc.EndSessionRequest)
	if err := codec.Decode(req, form, converters); err != nil {
		return nil, err
	}
	return req, nil
}

func validateEndSessionRequest(ctx context.Context, req *oidc.EndSessionRequest) (*storm.EndSessionRequest, error) {
	session := &storm.EndSessionRequest{}

	// TODO: Validate id_token_hint if present (requires IDTokenHintVerifier)
	// TODO: Validate post_logout_redirect_uri against client configuration
	// TODO: Extract client_id and validate

	if req.State != "" {
		// State will be included in the redirect
	}

	return session, nil
}
