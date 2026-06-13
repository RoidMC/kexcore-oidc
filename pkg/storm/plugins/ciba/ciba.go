// Package ciba implements the OpenID Connect Client-Initiated Backchannel Authentication (CIBA) plugin.
//
// It handles POST /bc-authorize (CIBA Core 1.0 §7.1) and an optional
// approval page for users to approve/deny pending authentication requests.
// The ciba grant type on the token endpoint is handled by the Token plugin.
package ciba

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

const csrfCookieName = "ciba_csrf"

// init self-registers the CIBA plugin in the global registry.
func init() {
	storm.RegisterPlugin("ciba", storm.PriorityCIBA, func(ctx *storm.PluginContext) storm.Plugin {
		cibaStore, ok := ctx.Storage.(storm.CIBAStore)
		if !ok {
			return nil
		}
		cs, ok := ctx.Storage.(storm.ClientStore)
		if !ok {
			return nil
		}
		p := &Plugin{
			store:       cibaStore,
			clientStore: cs,
			lifetime:    5 * time.Minute,
			interval:    5 * time.Second,
			cibaTmpl:    cibaTmpl,
		}
		if nc, ok := ctx.Storage.(storm.CIBANotificationCallback); ok {
			p.notifier = nc
		}
		return p
	})
}

// Category returns CategoryStandard — CIBA is optional but enabled by default.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string {
	return []string{"CIBAStore", "ClientStore"}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "ciba" }

// Register installs the /bc-authorize and /ciba routes.
func (p *Plugin) Register(r chi.Router) {
	r.Post("/bc-authorize", p.handleBackchannelAuth)
	r.Get("/ciba", p.handleApprovalPage)
	r.Post("/ciba", p.handleApprovalAction)
}

// Contribute adds CIBA discovery fields per CIBA Core 1.0 §4.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.BackchannelAuthenticationEndpoint = shared.EndpointURL(ctx, protocol.NewEndpoint("/bc-authorize"))
	cfg.GrantTypesSupported = append(cfg.GrantTypesSupported,
		string(protocol.GrantTypeCIBA),
	)
}

// handleBackchannelAuth handles POST /bc-authorize (CIBA Core 1.0 §7.1.1).
func (p *Plugin) handleBackchannelAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	// CIBA Core 1.0 §7.1.1: client authentication is required
	clientID, clientSecret, authErr := validateClientAuth(r)
	if authErr != nil {
		shared.WriteError(w, r, authErr, nil)
		return
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithParent(err), nil)
		return
	}

	// CIBA Core 1.0 §7.1.1: client must have the CIBA grant type
	if !validateCIBAGrantType(client) {
		shared.WriteError(w, r, protocol.ErrUnauthorizedClient().WithDescription("client missing grant_type urn:openid:params:grant-type:ciba"), nil)
		return
	}

	if err := p.clientStore.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	// At least one hint required
	loginHint := strings.TrimSpace(r.Form.Get("login_hint"))
	idTokenHint := strings.TrimSpace(r.Form.Get("id_token_hint"))
	loginHintToken := strings.TrimSpace(r.Form.Get("login_hint_token"))

	if loginHint == "" && idTokenHint == "" && loginHintToken == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("at least one of login_hint, id_token_hint, or login_hint_token is required"), nil)
		return
	}

	subject := loginHint
	if subject == "" && idTokenHint != "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("id_token_hint parsing not yet implemented; use login_hint"), nil)
		return
	}

	bindingMessage := strings.TrimSpace(r.Form.Get("binding_message"))
	userCode := strings.TrimSpace(r.Form.Get("user_code"))

	// CIBA Core 1.0 §7.1.1: requested_expiry is an optional positive integer
	// allowing the client to request the expires_in value for the auth_req_id.
	lifetime := p.lifetime
	if requestedExpiry := r.Form.Get("requested_expiry"); requestedExpiry != "" {
		if secs, err := strconv.Atoi(requestedExpiry); err == nil && secs > 0 {
			requested := time.Duration(secs) * time.Second
			if requested < lifetime {
				lifetime = requested
			}
		}
	}

	deliveryMode := protocol.CIBAModePoll
	clientNotificationToken := strings.TrimSpace(r.Form.Get("client_notification_token"))
	if clientNotificationToken != "" {
		deliveryMode = protocol.CIBAModePing
	}

	authReqID, err := generateRandomID(32)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithDescription("error generating auth request ID").WithParent(err), nil)
		return
	}

	cibaReq := &storm.CIBARequest{
		AuthReqID:               authReqID,
		ClientID:                clientID,
		Scope:                   r.Form.Get("scope"),
		Subject:                 subject,
		BindingMessage:          bindingMessage,
		UserCode:                userCode,
		RequestedScopes:         strings.Fields(r.Form.Get("scope")),
		ExpiresAt:               time.Now().Add(lifetime),
		Status:                  protocol.CIBAStatusPending,
		DeliveryMode:            deliveryMode,
		ClientNotificationToken: clientNotificationToken,
	}

	if err := p.store.StoreCIBARequest(r.Context(), cibaReq); err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithDescription("error storing CIBA request").WithParent(err), nil)
		return
	}

	resp := protocol.NewBackchannelAuthResponse(authReqID, int(lifetime.Seconds()), int(p.interval.Seconds()))
	shared.JSONResponse(w, resp, http.StatusOK)
}

// handleApprovalPage handles GET /ciba — the CIBA approval page.
func (p *Plugin) handleApprovalPage(w http.ResponseWriter, r *http.Request) {
	authReqID := strings.TrimSpace(r.URL.Query().Get("auth_req_id"))

	var csrfToken string
	if p.csrfHandler != nil {
		csrfToken = generateCSRFToken()
		p.setCSRFCookie(w, csrfToken)
	}

	if authReqID == "" {
		p.renderApprovalPage(w, nil, "", csrfToken)
		return
	}

	req, err := p.store.GetCIBARequestByAuthReqID(r.Context(), authReqID)
	if err != nil {
		p.renderApprovalPage(w, nil, "Invalid or unknown authentication request.", csrfToken)
		return
	}

	if req.Status != protocol.CIBAStatusPending {
		p.renderApprovalPage(w, req, "This request has already been processed.", csrfToken)
		return
	}

	if time.Now().After(req.ExpiresAt) {
		p.renderApprovalPage(w, req, "This request has expired.", csrfToken)
		return
	}

	p.renderApprovalPage(w, req, "", csrfToken)
}

// handleApprovalAction handles POST /ciba — approve or deny a CIBA request.
func (p *Plugin) handleApprovalAction(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	if !p.validateCSRF(r) {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("invalid or missing CSRF token"), nil)
		return
	}

	authReqID := strings.TrimSpace(r.Form.Get("auth_req_id"))
	action := strings.TrimSpace(r.Form.Get("action"))

	if authReqID == "" || action == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("auth_req_id and action are required"), nil)
		return
	}

	req, err := p.store.GetCIBARequestByAuthReqID(r.Context(), authReqID)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("unknown auth_req_id"), nil)
		return
	}

	if req.Status != protocol.CIBAStatusPending {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("request already processed"), nil)
		return
	}

	if time.Now().After(req.ExpiresAt) {
		shared.WriteError(w, r, protocol.ErrExpiredDeviceCode().WithDescription("The auth_req_id has expired."), nil)
		return
	}

	switch action {
	case "approve":
		if err := p.store.UpdateCIBARequestStatus(r.Context(), authReqID, protocol.CIBAStatusApproved, req.RequestedScopes); err != nil {
			shared.WriteError(w, r, protocol.ErrServerError().WithDescription("error approving request").WithParent(err), nil)
			return
		}
		req.Status = protocol.CIBAStatusApproved
		req.ApprovedScopes = req.RequestedScopes
	case "deny":
		if err := p.store.UpdateCIBARequestStatus(r.Context(), authReqID, protocol.CIBAStatusDenied, nil); err != nil {
			shared.WriteError(w, r, protocol.ErrServerError().WithDescription("error denying request").WithParent(err), nil)
			return
		}
		req.Status = protocol.CIBAStatusDenied
	default:
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("invalid action: must be 'approve' or 'deny'"), nil)
		return
	}

	// CIBA Core 1.0 §10: notify the client if ping delivery mode
	p.notifyStatusChange(r.Context(), req)

	http.Redirect(w, r, "/ciba?"+url.Values{"auth_req_id": {authReqID}}.Encode(), http.StatusFound)
}

// renderApprovalPage renders the CIBA approval page template.
func (p *Plugin) renderApprovalPage(w http.ResponseWriter, req *storm.CIBARequest, errMsg string, csrfToken string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	data := map[string]interface{}{
		"Error":     errMsg,
		"CSRFToken": csrfToken,
	}

	if req != nil {
		data["AuthReqID"] = req.AuthReqID
		data["ClientID"] = req.ClientID
		data["Scope"] = req.Scope
		data["BindingMessage"] = req.BindingMessage
		data["UserCode"] = req.UserCode
	}

	if err := p.cibaTmpl.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// notifyStatusChange calls the notification callback if available.
// For ping delivery mode, this triggers the client notification endpoint.
// For poll delivery mode, this is a no-op (client polls the token endpoint).
// Errors are logged but do not affect the approval response.
func (p *Plugin) notifyStatusChange(ctx context.Context, req *storm.CIBARequest) {
	if p.notifier == nil {
		return
	}
	if req.DeliveryMode != protocol.CIBAModePing {
		return
	}
	if err := p.notifier.OnCIBAStatusChange(ctx, req); err != nil {
		// CIBA Core 1.0 §10.1: notification failures should not affect the flow.
		// The client will fall back to polling if notification fails.
	}
}

// setCSRFCookie writes a signed CSRF token cookie.
func (p *Plugin) setCSRFCookie(w http.ResponseWriter, token string) {
	if p.csrfHandler == nil {
		return
	}
	cookie, err := p.csrfHandler.CreateCookie(csrfCookieName, token)
	if err != nil {
		return
	}
	http.SetCookie(w, cookie)
}

// validateCSRF checks the CSRF cookie matches the form value.
func (p *Plugin) validateCSRF(r *http.Request) bool {
	if p.csrfHandler == nil {
		return true
	}
	cookieVal, err := p.csrfHandler.CheckCookie(r, csrfCookieName)
	if err != nil {
		return false
	}
	formToken := r.Form.Get("csrf_token")
	return formToken != "" && cookieVal == formToken
}

// generateRandomID generates a random hex string of the given byte length.
func generateRandomID(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateCSRFToken generates a random CSRF token.
func generateCSRFToken() string {
	token, err := generateRandomID(16)
	if err != nil {
		return ""
	}
	return token
}

// validateClientAuth extracts client credentials from the request.
func validateClientAuth(r *http.Request) (clientID, clientSecret string, err *protocol.Error) {
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		return clientID, clientSecret, nil
	}
	clientID = strings.TrimSpace(r.Form.Get("client_id"))
	clientSecret = strings.TrimSpace(r.Form.Get("client_secret"))
	if clientID == "" {
		return "", "", protocol.ErrInvalidClient().WithDescription("client_id is required")
	}
	return clientID, clientSecret, nil
}

// validateCIBAGrantType checks if the client has the CIBA grant type.
func validateCIBAGrantType(client storm.Client) bool {
	type grantTypesProvider interface {
		GrantTypes() []protocol.GrantType
	}
	if gp, ok := client.(grantTypesProvider); ok {
		for _, gt := range gp.GrantTypes() {
			if gt == protocol.GrantTypeCIBA {
				return true
			}
		}
		return false
	}
	return true
}
