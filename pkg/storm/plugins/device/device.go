// Package device implements the OAuth 2.0 Device Authorization Grant plugin.
//
// It handles POST /device_authorization (RFC 8628 §3.1), the
// GET/POST /device verification page (RFC 8628 §3.3), and the
// device_code grant type on the token endpoint (RFC 8628 §3.4).
package device

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// init self-registers the device plugin in the global registry.
func init() {
	storm.RegisterPlugin("device", storm.PriorityDevice, func(ctx *storm.PluginContext) storm.Plugin {
		das, ok := ctx.Storage.(storm.DeviceAuthStore)
		if !ok {
			return nil
		}
		cs, ok := ctx.Storage.(storm.ClientStore)
		if !ok {
			return nil
		}
		ts, ok := ctx.Storage.(storm.TokenStore)
		if !ok {
			return nil
		}
		ks, ok := ctx.Storage.(storm.KeyStore)
		if !ok {
			return nil
		}
		return &Plugin{
			store:       das,
			clientStore: cs,
			tokenStore:  ts,
			keyStore:    ks,
			lifetime:    15 * time.Minute,
			interval:    5 * time.Second,
			deviceTmpl:  deviceTmpl,
		}
	})
}

// Category returns CategoryStandard — device is optional but enabled by default.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string {
	return []string{"DeviceAuthStore", "ClientStore"}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "device" }

// Register installs the /device_authorization and /device routes.
func (p *Plugin) Register(r chi.Router) {
	r.Post("/device_authorization", p.handleDeviceAuthorization)
	r.Get("/device", p.handleDevicePage)
	r.Post("/device", p.handleDeviceApproval)
}

// Contribute returns the discovery fields for the device authorization endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.DeviceAuthorizationEndpoint = shared.EndpointURL(ctx, protocol.NewEndpoint("/device_authorization"))
	cfg.GrantTypesSupported = append(cfg.GrantTypesSupported,
		string(protocol.GrantTypeDeviceCode),
	)
}

// handleDeviceAuthorization handles POST /device_authorization (RFC 8628 §3.1).
func (p *Plugin) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	clientID, clientSecret, scopes, err := validateDeviceAuthorizationRequest(r)
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

	deviceCode := generateRandomCode(32)
	userCode := generateRandomUserCode(8)

	if err := p.store.StoreDeviceAuthorization(r.Context(), clientID, deviceCode, userCode, time.Now().Add(p.lifetime), scopes); err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error storing device authorization"), nil)
		return
	}

	issuer := shared.IssuerFromContext(r.Context())

	resp := &protocol.DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         issuer + "/device",
		VerificationURIComplete: issuer + "/device?user_code=" + userCode,
		ExpiresIn:               int(p.lifetime.Seconds()),
		Interval:                int(p.interval.Seconds()),
	}

	shared.JSONResponse(w, resp, http.StatusOK)
}

// handleDevicePage handles GET /device — the device verification page.
// Users enter their user_code here to review and approve/deny the authorization.
func (p *Plugin) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		p.renderDevicePage(w, "", "", "", "")
		return
	}

	state, err := p.store.GetDeviceAuthorizationByUserCode(r.Context(), userCode)
	if err != nil {
		p.renderDevicePage(w, userCode, "", "", "Invalid or unknown user code.")
		return
	}

	if deviceCodeExpired(state) {
		p.renderDevicePage(w, userCode, state.ClientID, formatScopes(state.Scopes), "This code has expired.")
		return
	}

	if state.Done {
		p.renderDevicePage(w, userCode, state.ClientID, formatScopes(state.Scopes), "This code has already been approved.")
		return
	}

	if state.Denied {
		p.renderDevicePage(w, userCode, state.ClientID, formatScopes(state.Scopes), "This code has been denied.")
		return
	}

	p.renderDevicePage(w, userCode, state.ClientID, formatScopes(state.Scopes), "")
}

// handleDeviceApproval handles POST /device — approve or deny the device authorization.
func (p *Plugin) handleDeviceApproval(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	userCode := r.Form.Get("user_code")
	action := r.Form.Get("action")
	subject := r.Form.Get("subject")

	if userCode == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("user_code is required"), nil)
		return
	}

	if action == "deny" {
		if err := p.store.DenyDeviceAuthorization(r.Context(), userCode); err != nil {
			shared.WriteError(w, r, protocol.DefaultToServerError(err, "error denying device authorization"), nil)
			return
		}
		p.renderDevicePage(w, userCode, "", "", "Authorization denied.")
		return
	}

	// subject must be provided by the authentication middleware/session layer
	if subject == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("subject is required (provide via authenticated session)"), nil)
		return
	}
	if err := p.store.ApproveDeviceAuthorization(r.Context(), userCode, subject); err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error approving device authorization"), nil)
		return
	}
	p.renderDevicePage(w, userCode, "", "", "Authorization approved. You may close this window.")
}

// renderDevicePage renders the device verification page template.
func (p *Plugin) renderDevicePage(w http.ResponseWriter, userCode, clientID, scopes, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if errMsg != "" && strings.Contains(errMsg, "Invalid") {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = p.deviceTmpl.Execute(w, map[string]string{
		"UserCode": userCode,
		"ClientID": clientID,
		"Scopes":   scopes,
		"Error":    errMsg,
	})
}
