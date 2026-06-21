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

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
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
		return &Plugin{
			store:       das,
			clientStore: cs,
			clientAuth: storm.NewClientAuthHelper(cs).
				WithTLSSkipVerify(ctx.SkipTLSCertVerify).
				WithAllowPrivateIPs(ctx.AllowPrivateIPs),
			lifetime:        15 * time.Minute,
			interval:        5 * time.Second,
			deviceTmpl:      deviceTmpl,
			endpointConfigs: ctx.EndpointConfigs,
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
	deviceAuthPath := p.getRoutePath("device", "/device_authorization")
	devicePagePath := p.getRoutePath("device_page", "/device")
	r.Post(deviceAuthPath, p.handleDeviceAuthorization)
	r.Get(devicePagePath, p.handleDevicePage)
	r.Post(devicePagePath, p.handleDeviceApproval)
}

// Contribute returns the discovery fields for the device authorization endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.DeviceAuthorizationEndpoint = p.resolveEndpoint(ctx, "device", "/device_authorization")
	cfg.GrantTypesSupported = append(cfg.GrantTypesSupported,
		string(protocol.GrantTypeDeviceCode),
	)
}

// resolveEndpoint resolves the absolute URL for the given endpoint.
// If EndpointConfigs is configured, it uses that; otherwise it falls back
// to the default behavior of building the URL from the issuer in context.
func (p *Plugin) resolveEndpoint(ctx context.Context, endpointName, defaultPath string) string {
	if p.endpointConfigs != nil {
		defaultURL := shared.EndpointURL(ctx, protocol.NewEndpoint(defaultPath))
		return p.endpointConfigs.GetDiscoveryURL(endpointName, defaultURL)
	}
	return shared.EndpointURL(ctx, protocol.NewEndpoint(defaultPath))
}

// getRoutePath returns the route path for the given endpoint.
func (p *Plugin) getRoutePath(endpointName, defaultPath string) string {
	if p.endpointConfigs != nil {
		return p.endpointConfigs.GetRoutePath(endpointName, defaultPath)
	}
	return defaultPath
}

// handleDeviceAuthorization handles POST /device_authorization (RFC 8628 §3.1).
func (p *Plugin) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	// Extract scopes from the request (client_id/client_secret may come from form or assertion).
	scopes := r.Form["scope"]

	// Authenticate the client using the shared helper (supports private_key_jwt, tls_client_auth, basic/form).
	client, err := p.clientAuth.AuthenticateClient(r)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}
	clientID := client.GetID()

	// RFC 8628 §3.1: client must have device_code grant type
	if sc, ok := client.(storm.Client); ok && !validateDeviceGrantType(sc) {
		shared.WriteError(w, r, protocol.ErrUnauthorizedClient().WithDescription("client missing grant_type device_code"), nil)
		return
	}

	deviceCode := generateRandomCode(32)
	userCode, err := generateUniqueUserCode(r.Context(), p.store, p.maxUserCodeRetries)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

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

	// Per-client poll interval override
	if client != nil {
		if dpic, ok := client.(storm.DevicePollIntervalClient); ok {
			if d := dpic.DevicePollInterval(); d > 0 {
				resp.Interval = int(d.Seconds())
			}
		}
	}

	shared.JSONResponse(w, resp, http.StatusOK)
}

// handleDevicePage handles GET /device — the device verification page.
// Users enter their user_code here to review and approve/deny the authorization.
func (p *Plugin) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	userCode := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("user_code")))

	// Generate CSRF token for the form if protection is enabled
	var csrfToken string
	if p.csrfHandler != nil {
		csrfToken = generateCSRFToken()
		p.setCSRFCookie(w, csrfToken)
	}

	if userCode == "" {
		p.renderDevicePage(w, "", "", "", "", csrfToken)
		return
	}

	state, err := p.store.GetDeviceAuthorizationByUserCode(r.Context(), userCode)
	if err != nil {
		p.renderDevicePage(w, userCode, "", "", "Invalid or unknown user code.", csrfToken)
		return
	}

	if deviceCodeExpired(state) {
		p.renderDevicePage(w, userCode, state.ClientID, formatScopes(state.Scopes), "This code has expired.", csrfToken)
		return
	}

	if state.Done {
		p.renderDevicePage(w, userCode, state.ClientID, formatScopes(state.Scopes), "This code has already been approved.", csrfToken)
		return
	}

	if state.Denied {
		p.renderDevicePage(w, userCode, state.ClientID, formatScopes(state.Scopes), "This code has been denied.", csrfToken)
		return
	}

	p.renderDevicePage(w, userCode, state.ClientID, formatScopes(state.Scopes), "", csrfToken)
}

// handleDeviceApproval handles POST /device — approve or deny the device authorization.
func (p *Plugin) handleDeviceApproval(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	if !p.validateCSRF(r) {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("invalid or missing CSRF token"), nil)
		return
	}

	userCode := strings.ToUpper(strings.TrimSpace(r.Form.Get("user_code")))
	action := r.Form.Get("action")
	subject := strings.TrimSpace(r.Form.Get("subject"))

	if userCode == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("user_code is required"), nil)
		return
	}

	if action == "deny" {
		if err := p.store.DenyDeviceAuthorization(r.Context(), userCode); err != nil {
			shared.WriteError(w, r, protocol.DefaultToServerError(err, "error denying device authorization"), nil)
			return
		}
		p.renderDevicePage(w, userCode, "", "", "Authorization denied.", "")
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
	p.renderDevicePage(w, userCode, "", "", "Authorization approved. You may close this window.", "")
}

// renderDevicePage renders the device verification page template.
func (p *Plugin) renderDevicePage(w http.ResponseWriter, userCode, clientID, scopes, errMsg, csrfToken string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if errMsg != "" && strings.Contains(errMsg, "Invalid") {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = p.deviceTmpl.Execute(w, map[string]string{
		"UserCode":  userCode,
		"ClientID":  clientID,
		"Scopes":    scopes,
		"Error":     errMsg,
		"CSRFToken": csrfToken,
	})
}
