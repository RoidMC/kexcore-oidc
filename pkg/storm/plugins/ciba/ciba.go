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
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
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
			store:             cibaStore,
			clientStore:       cs,
			lifetime:          5 * time.Minute, // default, can be overridden via CIBAConfig.Lifetime
			interval:          5 * time.Second,
			cibaTmpl:          cibaTmpl,
			skipTLSCertVerify: ctx.SkipTLSCertVerify,
			allowPrivateIPs:   ctx.AllowPrivateIPs,
			endpointConfigs:   ctx.EndpointConfigs,
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
	bcAuthPath := p.getRoutePath("ciba", "/bc-authorize")
	cibaPagePath := p.getRoutePath("ciba_page", "/ciba")
	r.Post(bcAuthPath, p.handleBackchannelAuth)
	r.Get(cibaPagePath, p.handleApprovalPage)
	r.Post(cibaPagePath, p.handleApprovalAction)
	// Automated CIBA approval endpoint for OIDF conformance testing.
	// No CSRF protection — only for automated test environments.
	r.Post(cibaPagePath+"/approve", p.handleAutomatedApproval)
}

// Contribute adds CIBA discovery fields per CIBA Core 1.0 §4.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.BackchannelAuthenticationEndpoint = p.resolveEndpoint(ctx, "ciba", "/bc-authorize")
	cfg.GrantTypesSupported = append(cfg.GrantTypesSupported,
		string(protocol.GrantTypeCIBA),
	)
	cfg.BackchannelTokenDeliveryModesSupported = []string{string(protocol.CIBAModePoll), string(protocol.CIBAModePing)}
	// CIBA signed request object verification uses the same algorithms as
	// regular request objects. The discovery plugin sets this first.
	if len(cfg.RequestObjectSigningAlgValuesSupported) > 0 {
		cfg.BackchannelAuthenticationRequestSigningAlgValuesSupported = cfg.RequestObjectSigningAlgValuesSupported
	}
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

// handleBackchannelAuth handles POST /bc-authorize (CIBA Core 1.0 §7.1.1).
func (p *Plugin) handleBackchannelAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	// DEBUG: dump all form keys
	formKeys := make([]string, 0, len(r.Form))
	for k := range r.Form {
		formKeys = append(formKeys, k)
	}
	slog.Debug("ciba bc-authorize", "form_keys", formKeys, "form_client_id", r.Form.Get("client_id"), "has_request", r.Form.Get("request") != "", "has_assertion", r.Form.Get("client_assertion") != "")

	// CIBA Core 1.0 §7: client authentication is required for bc-authorize
	// The authentication method depends on the client's registered token_endpoint_auth_method:
	// - private_key_jwt: requires client_assertion
	// - tls_client_auth: accepts mTLS client certificate

	var client storm.Client
	var clientID string

	// RFC 7523 §2.2: client_assertion (private_key_jwt) takes precedence
	if assertionType := r.Form.Get("client_assertion_type"); assertionType == protocol.ClientAssertionTypeJWTAssertion {
		assertion := r.Form.Get("client_assertion")
		if assertion == "" {
			shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("client_assertion is missing"), nil)
			return
		}
		issuer := shared.IssuerFromContext(r.Context())
		bcEndpoint := shared.EndpointURL(r.Context(), protocol.NewEndpoint("/bc-authorize"))
		tokenEndpoint := shared.EndpointURL(r.Context(), protocol.NewEndpoint("/token"))
		slog.Debug("ciba bc-authorize: authenticating client",
			"issuer", issuer,
			"bcEndpoint", bcEndpoint,
		)
		getClient := func(ctx context.Context, cid string) (shared.Client, error) {
			return p.clientStore.GetClientByClientID(ctx, cid)
		}
		getAudiences := func(c shared.Client) []string {
			// FAPI CIBA: accept issuer URL, bc-authorize endpoint, and token endpoint.
			// OIDF conformance suite may send any of these as the audience.
			return []string{issuer, bcEndpoint, tokenEndpoint}
		}
		authenticatedClient, err := shared.AuthenticatePrivateKeyJWT(r, getClient, assertion, getAudiences, p.skipTLSCertVerify, p.allowPrivateIPs)
		if err != nil {
			slog.Debug("ciba bc-authorize: client authentication failed", "error", err)
			shared.WriteError(w, r, protocol.ErrInvalidClient().WithParent(err), nil)
			return
		}
		client = authenticatedClient.(storm.Client)
		clientID = client.GetID()
	} else {
		// No client_assertion — check client's registered auth method
		cid, clientSecret, authErr := validateClientAuth(r)
		if authErr != nil {
			shared.WriteError(w, r, authErr, nil)
			return
		}
		clientID = cid
		var err error
		client, err = p.clientStore.GetClientByClientID(r.Context(), clientID)
		if err != nil {
			shared.WriteError(w, r, protocol.ErrInvalidClient().WithParent(err), nil)
			return
		}
		cert := shared.ClientCertFromContext(r.Context())
		if client.AuthMethod() == protocol.AuthMethodTLSClientAuth {
			// tls_client_auth: require mTLS certificate
			if cert == nil {
				shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("mTLS client certificate is required for tls_client_auth client"), nil)
				return
			}
			// Optional: client-level certificate identity validation (RFC 8705 §2.1)
			if v, ok := client.(shared.ClientCertBoundAuthenticator); ok {
				if err := v.ValidateClientCert(cert, clientID); err != nil {
					shared.WriteError(w, r, protocol.ErrInvalidClient().WithParent(err), nil)
					return
				}
			}
		} else if client.AuthMethod() == protocol.AuthMethodPrivateKeyJWT {
			// private_key_jwt: require client_assertion, no mTLS fallback
			shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("client_assertion is required for private_key_jwt client"), nil)
			return
		} else {
			// Other auth methods: basic auth / form-based client_secret
			if err := p.clientStore.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
				shared.WriteError(w, r, err, nil)
				return
			}
		}
	}

	// CIBA Core 1.0 §7.1.1: client must have the CIBA grant type
	if !validateCIBAGrantType(client) {
		shared.WriteError(w, r, protocol.ErrUnauthorizedClient().WithDescription("client missing grant_type urn:openid:params:grant-type:ciba"), nil)
		return
	}

	// FAPI-CIBA: signed request object is required for FAPI clients
	if fapi, ok := client.(storm.FAPIProfileProvider); ok && fapi.FAPIProfile() {
		if r.Form.Get("request") == "" {
			shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("signed request object is required for FAPI-CIBA"), nil)
			return
		}
	}

	// At least one hint required
	loginHint := strings.TrimSpace(r.Form.Get("login_hint"))
	idTokenHint := strings.TrimSpace(r.Form.Get("id_token_hint"))
	loginHintToken := strings.TrimSpace(r.Form.Get("login_hint_token"))

	// CIBA Core 1.0 §4: If a signed request object is present, parse and validate it.
	// The request object claims override form parameters.
	if requestParam := strings.TrimSpace(r.Form.Get("request")); requestParam != "" {
		cibaReqObj, err := p.parseCIBARequestObject(r.Context(), requestParam, clientID)
		if err != nil {
			shared.WriteError(w, r, err, nil)
			return
		}
		// Override form parameters with request object claims
		if cibaReqObj.LoginHint != "" {
			loginHint = cibaReqObj.LoginHint
		}
		if cibaReqObj.IDTokenHint != "" {
			idTokenHint = cibaReqObj.IDTokenHint
		}
		if cibaReqObj.LoginHintToken != "" {
			loginHintToken = cibaReqObj.LoginHintToken
		}
		if cibaReqObj.BindingMessage != "" {
			r.Form.Set("binding_message", cibaReqObj.BindingMessage)
		}
		if cibaReqObj.UserCode != "" {
			r.Form.Set("user_code", cibaReqObj.UserCode)
		}
		if cibaReqObj.RequestedExpiry > 0 {
			r.Form.Set("requested_expiry", strconv.Itoa(int(cibaReqObj.RequestedExpiry)))
		}
		if cibaReqObj.Scope != "" {
			r.Form.Set("scope", cibaReqObj.Scope)
		}
		if cibaReqObj.AcrValues != "" {
			r.Form.Set("acr_values", cibaReqObj.AcrValues)
		}
		if cibaReqObj.ClientNotificationToken != "" {
			r.Form.Set("client_notification_token", cibaReqObj.ClientNotificationToken)
		}
	}

	if loginHint == "" && idTokenHint == "" && loginHintToken == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("at least one of login_hint, id_token_hint, or login_hint_token is required"), nil)
		return
	}

	// CIBA Core 1.0 §7.2-3: only one hint should be provided
	hintsProvided := 0
	if loginHint != "" {
		hintsProvided++
	}
	if idTokenHint != "" {
		hintsProvided++
	}
	if loginHintToken != "" {
		hintsProvided++
	}
	if hintsProvided > 1 {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("only one of login_hint, id_token_hint, or login_hint_token should be provided"), nil)
		return
	}

	subject := loginHint
	if subject == "" && idTokenHint != "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("id_token_hint parsing not yet implemented; use login_hint"), nil)
		return
	}

	bindingMessage := strings.TrimSpace(r.Form.Get("binding_message"))

	// CIBA Core 1.0 §7.1: binding_message should be "short" and "human-readable".
	// If the binding message is too long, return invalid_binding_message error.
	// This is required for automated testing where the message cannot be displayed.
	const maxBindingMessageLength = 300
	if len(bindingMessage) > maxBindingMessageLength {
		shared.WriteError(w, r, protocol.ErrInvalidBindingMessage().WithDescription("binding_message exceeds maximum length of %d characters", maxBindingMessageLength), nil)
		return
	}

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

	slog.Debug("ciba bc-authorize: request created",
		"auth_req_id", authReqID,
		"client_id", clientID,
		"subject", subject,
		"delivery_mode", deliveryMode,
		"binding_message", bindingMessage,
	)

	resp := protocol.NewBackchannelAuthResponse(authReqID, int(lifetime.Seconds()), int(p.interval.Seconds()))
	shared.JSONResponse(w, resp, http.StatusOK)
}

// handleApprovalPage handles GET /ciba — the CIBA approval page.
func (p *Plugin) handleApprovalPage(w http.ResponseWriter, r *http.Request) {
	authReqID := strings.TrimSpace(r.URL.Query().Get("auth_req_id"))

	slog.Debug("ciba GET /ciba: approval page accessed",
		"auth_req_id", authReqID,
		"url", r.URL.String(),
	)

	var csrfToken string
	if p.csrfHandler != nil {
		csrfToken = generateCSRFToken()
		p.setCSRFCookie(w, csrfToken)
	}

	if authReqID == "" {
		slog.Debug("ciba GET /ciba: no auth_req_id, showing empty page")
		p.renderApprovalPage(w, nil, "", csrfToken)
		return
	}

	req, err := p.store.GetCIBARequestByAuthReqID(r.Context(), authReqID)
	if err != nil {
		slog.Debug("ciba GET /ciba: request not found", "auth_req_id", authReqID, "error", err)
		p.renderApprovalPage(w, nil, "Invalid or unknown authentication request.", csrfToken)
		return
	}

	slog.Debug("ciba GET /ciba: request found",
		"auth_req_id", authReqID,
		"client_id", req.ClientID,
		"status", req.Status,
		"subject", req.Subject,
	)

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
		slog.Debug("ciba POST /ciba: CSRF validation failed")
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("invalid or missing CSRF token"), nil)
		return
	}

	authReqID := strings.TrimSpace(r.Form.Get("auth_req_id"))
	action := strings.TrimSpace(r.Form.Get("action"))

	slog.Debug("ciba POST /ciba: approval action",
		"auth_req_id", authReqID,
		"action", action,
	)

	if authReqID == "" || action == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("auth_req_id and action are required"), nil)
		return
	}

	req, err := p.store.GetCIBARequestByAuthReqID(r.Context(), authReqID)
	if err != nil {
		slog.Debug("ciba POST /ciba: request not found", "auth_req_id", authReqID, "error", err)
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("unknown auth_req_id"), nil)
		return
	}

	slog.Debug("ciba POST /ciba: request found",
		"auth_req_id", authReqID,
		"client_id", req.ClientID,
		"status", req.Status,
	)

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
		slog.Debug("ciba POST /ciba: request approved", "auth_req_id", authReqID)
	case "deny":
		if err := p.store.UpdateCIBARequestStatus(r.Context(), authReqID, protocol.CIBAStatusDenied, nil); err != nil {
			shared.WriteError(w, r, protocol.ErrServerError().WithDescription("error denying request").WithParent(err), nil)
			return
		}
		req.Status = protocol.CIBAStatusDenied
		slog.Debug("ciba POST /ciba: request denied", "auth_req_id", authReqID)
	default:
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("invalid action: must be 'approve' or 'deny'"), nil)
		return
	}

	// CIBA Core 1.0 §10: notify the client if ping delivery mode
	p.notifyStatusChange(r.Context(), req)

	http.Redirect(w, r, "/ciba?"+url.Values{"auth_req_id": {authReqID}}.Encode(), http.StatusFound)
}

// handleAutomatedApproval handles POST /ciba/approve — automated CIBA approval for testing.
// No CSRF protection. Only for OIDF conformance testing.
// URL template: /ciba/approve?token={auth_req_id}&type={action}
func (p *Plugin) handleAutomatedApproval(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	// OIDF conformance suite sends: token={auth_req_id}&type={action}
	authReqID := strings.TrimSpace(r.Form.Get("token"))
	action := strings.TrimSpace(r.Form.Get("type"))

	slog.Debug("ciba POST /ciba/approve: automated approval",
		"auth_req_id", authReqID,
		"action", action,
	)

	if authReqID == "" || action == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("token and type are required"), nil)
		return
	}

	req, err := p.store.GetCIBARequestByAuthReqID(r.Context(), authReqID)
	if err != nil {
		slog.Debug("ciba POST /ciba/approve: request not found", "auth_req_id", authReqID, "error", err)
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
	case "allow":
		if err := p.store.UpdateCIBARequestStatus(r.Context(), authReqID, protocol.CIBAStatusApproved, req.RequestedScopes); err != nil {
			shared.WriteError(w, r, protocol.ErrServerError().WithDescription("error approving request").WithParent(err), nil)
			return
		}
		req.Status = protocol.CIBAStatusApproved
		req.ApprovedScopes = req.RequestedScopes
		slog.Debug("ciba POST /ciba/approve: request approved", "auth_req_id", authReqID)
	case "deny":
		if err := p.store.UpdateCIBARequestStatus(r.Context(), authReqID, protocol.CIBAStatusDenied, nil); err != nil {
			shared.WriteError(w, r, protocol.ErrServerError().WithDescription("error denying request").WithParent(err), nil)
			return
		}
		req.Status = protocol.CIBAStatusDenied
		slog.Debug("ciba POST /ciba/approve: request denied", "auth_req_id", authReqID)
	default:
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("invalid type: must be 'allow' or 'deny'"), nil)
		return
	}

	// CIBA Core 1.0 §10: notify the client if ping delivery mode
	p.notifyStatusChange(r.Context(), req)

	shared.JSONResponse(w, map[string]string{"status": string(req.Status)}, http.StatusOK)
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
//
// SSRF protection: when allowPrivateIPs is false (production default), the
// client's notification endpoint URL is validated via shared.ValidateRemoteURL.
// For CIDR-level allowlisting, developers implement their own URL validation
// in the CIBANotificationCallback before making outbound requests.
func (p *Plugin) notifyStatusChange(ctx context.Context, req *storm.CIBARequest) {
	if p.notifier == nil {
		return
	}
	if req.DeliveryMode != protocol.CIBAModePing {
		return
	}
	// SSRF protection: validate notification endpoint URL unless allowPrivateIPs.
	if !p.allowPrivateIPs {
		if err := p.validateNotificationEndpoint(ctx, req.ClientID); err != nil {
			slog.Warn("[CIBA] notification endpoint SSRF validation failed, skipping notification",
				"client_id", req.ClientID, "error", err)
			return
		}
	}
	if err := p.notifier.OnCIBAStatusChange(ctx, req); err != nil {
		// CIBA Core 1.0 §10.1: notification failures should not affect the flow.
		// The client will fall back to polling if notification fails.
	}
}

// validateNotificationEndpoint looks up the client's notification endpoint URL
// and validates it against SSRF restrictions (private/link-local IPs blocked).
func (p *Plugin) validateNotificationEndpoint(ctx context.Context, clientID string) error {
	client, err := p.clientStore.GetClientByClientID(ctx, clientID)
	if err != nil {
		return fmt.Errorf("client lookup failed: %w", err)
	}
	nep, ok := client.(storm.NotificationEndpointProvider)
	if !ok {
		// Client doesn't implement NotificationEndpointProvider — no URL to validate.
		return nil
	}
	endpoint := nep.NotificationEndpoint()
	if endpoint == "" {
		return nil
	}
	return shared.ValidateRemoteURL(endpoint)
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

// parseCIBARequestObject parses and validates a signed CIBA authentication request JWT
// (CIBA Core 1.0 §4). It validates iss, aud, time claims, and the signature using the
// client's registered JWKS.
func (p *Plugin) parseCIBARequestObject(ctx context.Context, requestParam, expectedClientID string) (*protocol.CIBARequestObject, error) {
	requestObject := new(protocol.CIBARequestObject)
	payload, err := protocol.ParseToken(requestParam, requestObject)
	if err != nil {
		return nil, protocol.ErrInvalidRequest().WithDescription("invalid CIBA request object").WithParent(err)
	}

	// Validate issuer (must be the client_id)
	if requestObject.Issuer == "" {
		return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object missing iss claim")
	}
	if requestObject.Issuer != expectedClientID {
		// Check if the iss is a known client (to distinguish between
		// "bad iss" (unknown client) and "different client_id and issuer" (known but wrong client))
		issClient, issClientErr := p.clientStore.GetClientByClientID(ctx, requestObject.Issuer)
		slog.Debug("ciba request object iss mismatch",
			"request_object_iss", requestObject.Issuer,
			"expected_client_id", expectedClientID,
			"iss_is_known_client", issClientErr == nil,
			"iss_client_auth_method", func() string {
				if issClient != nil {
					return string(issClient.AuthMethod())
				}
				return "N/A"
			}(),
			"request_aud", requestObject.Audience,
			"request_login_hint", requestObject.LoginHint,
		)
		// CIBA Core 1.0 §4: iss in request object MUST match the client_id.
		// A mismatch is always a request validation error (invalid_request + 400),
		// not a client authentication error. The OIDF conformance suite
		// (CIBA-13 ensure-request-object-bad-iss-fails) expects this behavior
		// for all client auth types including tls_client_auth.
		return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object iss must match client_id")
	}

	// Validate audience (must contain the issuer)
	issuer := shared.IssuerFromContext(ctx)
	found := false
	for _, aud := range requestObject.Audience {
		if aud == issuer {
			found = true
			break
		}
	}
	if !found {
		return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object aud must contain the issuer")
	}

	// Look up client for signature verification
	client, err := p.clientStore.GetClientByClientID(ctx, expectedClientID)
	if err != nil {
		return nil, protocol.ErrInvalidRequest().WithDescription("client not found for request object verification")
	}

	// Get client's JWKS for signature verification
	clientKS, ok := client.(shared.JWKSProvider)
	if !ok {
		return nil, protocol.ErrInvalidRequest().WithDescription("client does not support request object verification")
	}

	var clientKeys []jwk.Key
	if uriProvider, ok := client.(shared.JWKSURIProvider); ok && uriProvider.ClientJWKSURI() != "" {
		fetchedKeys, err := shared.FetchJWKSFromURI(uriProvider.ClientJWKSURI(), p.skipTLSCertVerify, p.allowPrivateIPs)
		if err != nil {
			clientKeys = clientKS.ClientJWKS()
		} else {
			clientKeys = fetchedKeys
		}
	} else {
		clientKeys = clientKS.ClientJWKS()
	}

	if len(clientKeys) == 0 {
		return nil, protocol.ErrInvalidRequest().WithDescription("client has no registered keys")
	}

	// Verify signature
	if err := verifyRequestObjectSignature(requestParam, payload, clientKeys); err != nil {
		return nil, protocol.ErrInvalidRequest().WithDescription("invalid CIBA request object signature").WithParent(err)
	}

	// Validate time claims
	now := time.Now()
	const clockSkew = 10 * time.Second
	const maxExpFuture = 30 * time.Minute // CIBA request object exp must not be too far in the future

	// CIBA Core 1.0 §4: request object MUST contain exp claim
	if requestObject.ExpiresAt == 0 {
		return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object missing exp claim")
	}
	if now.After(time.Unix(requestObject.ExpiresAt, 0).Add(clockSkew)) {
		return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object has expired")
	}
	if time.Unix(requestObject.ExpiresAt, 0).Sub(now) > maxExpFuture+clockSkew {
		return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object exp is too far in the future")
	}

	// CIBA Core 1.0 §4: request object MUST contain iat claim
	if requestObject.IssuedAt == 0 {
		return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object missing iat claim")
	}

	// CIBA Core 1.0 §4: request object MUST contain nbf claim
	if requestObject.NotBefore == 0 {
		return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object missing nbf claim")
	}
	// Validate nbf: must not be too far in the future or too far in the past
	{
		nbfTime := time.Unix(requestObject.NotBefore, 0)
		if now.Before(nbfTime.Add(-clockSkew)) {
			return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object is not yet valid (nbf)")
		}
		if now.Sub(nbfTime) > maxExpFuture+clockSkew {
			return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object nbf is too far in the past")
		}
	}

	// CIBA Core 1.0 §4: request object MUST contain jti claim
	if requestObject.JTI == "" {
		return nil, protocol.ErrInvalidRequest().WithDescription("CIBA request object missing jti claim")
	}

	return requestObject, nil
}

// verifyRequestObjectSignature verifies the JWS signature of a request object
// against the provided client keys.
func verifyRequestObjectSignature(tokenString string, payload []byte, clientKeys []jwk.Key) error {
	keySet := jwk.NewSet()
	for _, key := range clientKeys {
		keySet.AddKey(key)
	}
	_, err := jws.Verify([]byte(tokenString), jws.WithKeySet(keySet))
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}
