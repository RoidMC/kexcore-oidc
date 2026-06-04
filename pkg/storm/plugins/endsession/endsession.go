// Package endsession implements the OIDC RP-Initiated Logout endpoint plugin.
//
// It handles GET/POST /end_session (OIDC Session Management §5),
// allowing relying parties to initiate logout of the end-user.
package endsession

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the OIDC End Session endpoint.
type Plugin struct {
	store            storm.SessionStore
	clientStore      storm.ClientStore
	keyStore         protocol.KeyStore
	defaultLogoutURI string
	offset           time.Duration
	maxAgeIAT        time.Duration
	maxAge           time.Duration
	decoder          *protocol.Decoder
}

// Config holds the dependencies for the EndSession plugin.
type Config struct {
	Store            storm.SessionStore
	ClientStore      storm.ClientStore
	KeyStore         protocol.KeyStore
	DefaultLogoutURI string
	// Offset is the clock skew tolerance for token validation (default: 0).
	Offset time.Duration
	// MaxAgeIAT is the maximum allowed age of the id_token_hint's iat claim.
	// Per OIDC Session Management §5, expired tokens can still be trusted for logout.
	// Set to 0 to disable iat_max_age checking.
	MaxAgeIAT time.Duration
	// MaxAge is the maximum allowed time since auth_time.
	// Set to 0 to disable auth_time max_age checking.
	MaxAge  time.Duration
	Decoder *protocol.Decoder
}

// New creates a new EndSession plugin from a PluginContext.
func New(ctx *storm.PluginContext) *Plugin {
	return &Plugin{
		store:            ctx.Storage.(storm.SessionStore),
		clientStore:      ctx.Storage.(storm.ClientStore),
		keyStore:         ctx.Storage.(storm.KeyStore),
		defaultLogoutURI: "/",
		decoder:          ctx.Decoder,
	}
}

// NewWithConfig creates a new EndSession plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	return &Plugin{
		store:            cfg.Store,
		clientStore:      cfg.ClientStore,
		keyStore:         cfg.KeyStore,
		defaultLogoutURI: cfg.DefaultLogoutURI,
		offset:           cfg.Offset,
		maxAgeIAT:        cfg.MaxAgeIAT,
		maxAge:           cfg.MaxAge,
		decoder:          cfg.Decoder,
	}
}

// init self-registers the endsession plugin in the global registry.
func init() {
	storm.RegisterPlugin("endsession", storm.PriorityEndSession, func(ctx *storm.PluginContext) storm.Plugin {
		return New(ctx)
	})
}

// Category returns CategoryStandard — endsession is optional but enabled by default.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string {
	return []string{"SessionStore", "ClientStore", "KeyStore"}
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
		"end_session_endpoint": shared.EndpointURL(ctx, protocol.NewEndpoint("/end_session")),
	}
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	req, err := parseEndSessionRequest(r.Form, p.decoder)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err), nil)
		return
	}

	session, err := validateEndSessionRequest(r.Context(), req, p)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	// Terminate the session
	if err := p.store.TerminateSession(r.Context(), session.UserID, session.ClientID); err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error terminating session"), nil)
		return
	}

	// Redirect to the post-logout URI or default
	redirectURI := session.RedirectURI
	if redirectURI == "" {
		redirectURI = p.defaultLogoutURI
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func parseEndSessionRequest(form map[string][]string, decoder *protocol.Decoder) (*protocol.EndSessionRequest, error) {
	req := new(protocol.EndSessionRequest)
	if err := decoder.Decode(req, form); err != nil {
		return nil, err
	}
	return req, nil
}

func validateEndSessionRequest(ctx context.Context, req *protocol.EndSessionRequest, p *Plugin) (*storm.EndSessionRequest, error) {
	session := &storm.EndSessionRequest{}

	// Validate id_token_hint per OIDC Session Management §5.
	// If present, extract the subject and validate client binding.
	// Expired tokens are treated as non-fatal - the claims can still
	// be trusted for logout purposes if signature validation passes.
	if req.IdTokenHint != "" {
		if p.keyStore == nil {
			return nil, protocol.ErrInvalidRequest().WithDescription("id_token_hint provided but IdTokenHintVerifier not configured")
		}

		v := &protocol.IDTokenHintVerifier{
			Issuer:    shared.IssuerFromContext(ctx),
			KeyStore:  p.keyStore,
			Offset:    p.offset,
			MaxAgeIAT: p.maxAgeIAT,
			MaxAge:    p.maxAge,
		}
		claims, err := protocol.VerifyIDTokenHint(ctx, req.IdTokenHint, v)
		if err != nil {
			var expired *protocol.IDTokenHintExpiredError
			if !errors.As(err, &expired) {
				return nil, protocol.ErrInvalidRequest().WithDescription("invalid id_token_hint").WithParent(err)
			}
		}

		if claims != nil {
			session.UserID = claims.Subject
			session.ClientID = claims.ClientID
			session.IDTokenHintClaims = claims
		}
	}

	// Validate requested client_id binding.
	if req.ClientID != "" {
		if session.ClientID != "" && req.ClientID != session.ClientID {
			return nil, protocol.ErrInvalidRequest().WithDescription("client_id does not match id_token_hint aud")
		}
		session.ClientID = req.ClientID
	}

	// Validate post_logout_redirect_uri against client configuration.
	if req.PostLogoutRedirectURI != "" && session.ClientID != "" {
		if p.clientStore != nil {
			client, err := p.clientStore.GetClientByClientID(ctx, session.ClientID)
			if err != nil {
				return nil, protocol.ErrInvalidRequest().WithDescription("invalid client_id").WithParent(err)
			}
			session.RedirectURI = validatePostLogoutRedirectURI(client, req.PostLogoutRedirectURI)
		} else {
			session.RedirectURI = req.PostLogoutRedirectURI
		}
	}

	if req.State != "" {
		// State will be included in the redirect
	}

	return session, nil
}

// validatePostLogoutRedirectURI checks if the given URI is valid for the client.
// Returns the validated URI or empty string if validation fails.
func validatePostLogoutRedirectURI(client storm.Client, uri string) string {
	type postLogoutRedirectURIsProvider interface {
		PostLogoutRedirectURIs() []string
	}
	if p, ok := client.(postLogoutRedirectURIsProvider); ok {
		for _, u := range p.PostLogoutRedirectURIs() {
			if u == uri {
				return uri
			}
		}
	}
	return ""
}
