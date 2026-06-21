// Package endsession implements the OIDC RP-Initiated Logout endpoint plugin.
//
// It handles GET/POST /end_session (OIDC Session Management §5),
// allowing relying parties to initiate logout of the end-user.
package endsession

import (
	"context"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

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
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.EndSessionEndpoint = p.resolveEndpoint(ctx, "endsession", "/end_session")
}

// resolveEndpoint resolves the absolute URL for the given endpoint.
// If an EndpointResolver is configured, it uses that; otherwise it falls back
// to the default behavior of building the URL from the issuer in context.
func (p *Plugin) resolveEndpoint(ctx context.Context, endpointName, defaultPath string) string {
	if p.endpointResolver != nil {
		return p.endpointResolver.Resolve(ctx, endpointName, defaultPath)
	}
	return shared.EndpointURL(ctx, protocol.NewEndpoint(defaultPath))
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

	// Per OIDC RP-Initiated Logout 1.0 §2: if post_logout_redirect_uri was
	// provided but not registered, the OP MUST NOT redirect to it.
	// Show an error page instead of performing the logout.
	if session.InvalidRedirectURI {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = p.logoutTmpl.Execute(w, map[string]string{
			"Title":   "Logout Error",
			"Heading": "Invalid post_logout_redirect_uri",
			"Message": "The provided post_logout_redirect_uri is not registered with this client.",
		})
		return
	}

	// Trigger post-logout hook BEFORE terminating session, so back-channel
	// logout can find the client sessions that need to be notified.
	if p.logoutHook != nil {
		sid := ""
		if session.IDTokenHintClaims != nil {
			sid = session.IDTokenHintClaims.SessionID
		}
		p.logoutHook.PostLogout(r.Context(), session.UserID, session.ClientID, sid)
	}

	// Terminate the session
	if err := p.store.TerminateSession(r.Context(), session.UserID, session.ClientID); err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error terminating session"), nil)
		return
	}

	// Redirect to the post-logout URI or show a logout confirmation page
	if session.RedirectURI != "" {
		redirectURI := session.RedirectURI
		// Append state to the redirect URI per OIDC Session Management §5.
		if session.State != "" {
			u, err := url.Parse(redirectURI)
			if err == nil {
				q := u.Query()
				q.Set("state", session.State)
				u.RawQuery = q.Encode()
				redirectURI = u.String()
			}
		}
		http.Redirect(w, r, redirectURI, http.StatusFound)
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = p.logoutTmpl.Execute(w, map[string]string{
			"Title":   "Logged Out",
			"Heading": "You have been logged out",
			"Message": "",
		})
	}
}
