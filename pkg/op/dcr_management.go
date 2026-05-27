// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios
//
// Dynamic Client Registration Management Protocol (RFC 7592) implementation.
//
// This file handles the client configuration endpoint for managing
// dynamically registered clients.

package op

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
)

// ClientConfigurationEndpoint handles RFC 7592 client management operations:
// GET, PUT, PATCH, DELETE /register/{client_id}
type ClientConfigurationEndpoint struct {
	Storage ClientRegistrationStorage
	Logger  *slog.Logger
}

// NewClientConfigurationEndpoint creates a new RFC 7592 endpoint handler.
func NewClientConfigurationEndpoint(storage ClientRegistrationStorage, logger *slog.Logger) *ClientConfigurationEndpoint {
	if logger == nil {
		logger = slog.Default()
	}
	return &ClientConfigurationEndpoint{
		Storage: storage,
		Logger:  logger,
	}
}

// Handle handles client configuration requests (RFC 7592).
func (e *ClientConfigurationEndpoint) Handle(w http.ResponseWriter, r *http.Request) {
	// Extract client_id from the path
	// Expected path: /register/{client_id}
	clientID := extractClientIDFromPath(r.URL.Path)
	if clientID == "" {
		e.writeError(w, http.StatusBadRequest, "invalid_client_metadata", "missing client_id in path")
		return
	}

	// Authenticate using registration access token (RFC 7592 Section 2.3)
	regAccessToken, err := e.authenticateRegistrationToken(r)
	if err != nil {
		e.Logger.Warn("dcr: registration access token validation failed", "error", err)
		e.writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	// Verify the token belongs to the requested client
	reg, err := e.Storage.GetClientRegistrationByToken(r.Context(), regAccessToken)
	if err != nil {
		e.Logger.Warn("dcr: registration access token not found", "error", err)
		e.writeError(w, http.StatusUnauthorized, "invalid_token", "invalid registration access token")
		return
	}
	if reg.ClientID != clientID {
		e.writeError(w, http.StatusForbidden, "invalid_grant", "token does not match requested client_id")
		return
	}

	switch r.Method {
	case http.MethodGet:
		e.getClientConfiguration(w, r, reg)
	case http.MethodPut:
		e.updateClientConfiguration(w, r, reg)
	case http.MethodDelete:
		e.deleteClientConfiguration(w, r, clientID)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// getClientConfiguration handles GET /register/{client_id} (RFC 7592 Section 2.1)
func (e *ClientConfigurationEndpoint) getClientConfiguration(w http.ResponseWriter, r *http.Request, reg *ClientRegistration) {
	resp := buildClientConfigurationResponse(reg)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		e.Logger.Error("dcr: failed to encode client configuration response", "error", err)
	}
}

// updateClientConfiguration handles PUT /register/{client_id} (RFC 7592 Section 2.2)
// PUT replaces the entire client metadata. Omitted fields are treated as null/empty.
func (e *ClientConfigurationEndpoint) updateClientConfiguration(w http.ResponseWriter, r *http.Request, reg *ClientRegistration) {
	var updateReq RegistrationUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		e.writeError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must be valid JSON")
		return
	}

	// Validate the update request (includes client_id match check per RFC 7592 Section 2.2)
	if err := e.validateUpdateRequest(&updateReq, reg.ClientID); err != nil {
		e.writeError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	// Update the client registration with full replacement semantics (RFC 7592 Section 2.2)
	updated, err := e.Storage.UpdateClientRegistration(r.Context(), reg.ClientID, &updateReq)
	if err != nil {
		e.Logger.Error("dcr: failed to update client registration", "error", err)
		e.writeError(w, http.StatusInternalServerError, "server_error", "internal server error")
		return
	}

	resp := buildClientConfigurationResponse(updated)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		e.Logger.Error("dcr: failed to encode client configuration response", "error", err)
	}
}

// deleteClientConfiguration handles DELETE /register/{client_id} (RFC 7592 Section 2.3)
func (e *ClientConfigurationEndpoint) deleteClientConfiguration(w http.ResponseWriter, r *http.Request, clientID string) {
	if err := e.Storage.DeleteClientRegistration(r.Context(), clientID); err != nil {
		e.Logger.Error("dcr: failed to delete client registration", "error", err)
		e.writeError(w, http.StatusInternalServerError, "server_error", "internal server error")
		return
	}

	e.Logger.Info("dcr: client registration deleted", "client_id", clientID)
	w.WriteHeader(http.StatusNoContent)
}

// authenticateRegistrationToken extracts and validates the registration access token.
func (e *ClientConfigurationEndpoint) authenticateRegistrationToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", oidc.ErrInvalidClient().WithDescription("authorization header required")
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		return "", oidc.ErrInvalidClient().WithDescription("bearer token required")
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "" {
		return "", oidc.ErrInvalidClient().WithDescription("bearer token is empty")
	}

	return token, nil
}

// validateUpdateRequest validates the update request fields (RFC 7592 Section 2.2).
// The request MUST include client_id and it must match the current client identifier.
// Omitted fields are treated as null/empty (to be deleted per RFC 7592).
func (e *ClientConfigurationEndpoint) validateUpdateRequest(req *RegistrationUpdateRequest, currentClientID string) error {
	// Validate client_id is present and matches
	if req.ClientID == "" {
		return oidc.ErrInvalidRequest().WithDescription("client_id is required in the update request")
	}
	if req.ClientID != currentClientID {
		return oidc.ErrInvalidRequest().WithDescription("client_id in request does not match the requested client")
	}

	// Validate redirect_uris if provided
	if len(req.RedirectURIs) == 0 && len(req.GrantTypes) == 0 {
		// If redirect_uris is empty and no grant_types specified, check if default grant type needs it
		// Per RFC 7591 Section 2, redirect_uris is REQUIRED for authorization_code or implicit
		// We'll do a basic check - if response_types contains "code" or "token", redirect_uris is needed
		for _, rt := range req.ResponseTypes {
			if rt == "code" || rt == "token" {
				return oidc.ErrInvalidRequest().WithDescription("redirect_uris is required for authorization_code or implicit flows")
			}
		}
	}
	for _, uri := range req.RedirectURIs {
		if uri == "" {
			return oidc.ErrInvalidRequest().WithDescription("redirect_uri cannot be empty")
		}
	}

	// Validate token_endpoint_auth_method if provided
	if req.TokenEndpointAuthMethod != "" {
		switch req.TokenEndpointAuthMethod {
		case "none", "client_secret_basic", "client_secret_post", "private_key_jwt":
			// valid
		default:
			return oidc.ErrInvalidRequest().WithDescription("unsupported token_endpoint_auth_method")
		}
	}

	return nil
}

// buildClientConfigurationResponse builds the response for GET/PUT operations.
func buildClientConfigurationResponse(reg *ClientRegistration) *ClientConfigurationResponse {
	resp := &ClientConfigurationResponse{
		ClientID:                reg.ClientID,
		ClientIDIssuedAt:        reg.ClientIDIssuedAt,
		ClientSecretExpiresAt:   reg.ClientSecretExpiresAt,
		RegistrationAccessToken: reg.RegistrationAccessToken,
		RegistrationURI:         reg.RegistrationURI,
	}

	// Include client metadata if available
	if reg.RegistrationRequest != nil {
		resp.RedirectURIs = reg.RedirectURIs
		resp.TokenEndpointAuthMethod = reg.TokenEndpointAuthMethod
		resp.GrantTypes = reg.GrantTypes
		resp.ResponseTypes = reg.ResponseTypes
		resp.ClientName = reg.ClientName
		resp.ClientURI = reg.ClientURI
		resp.LogoURI = reg.LogoURI
		resp.Scope = reg.Scope
		resp.Contacts = reg.Contacts
		resp.TosURI = reg.TosURI
		resp.PolicyURI = reg.PolicyURI
		resp.JwksURI = reg.JwksURI
		resp.Jwks = reg.Jwks
		resp.SoftwareID = reg.SoftwareID
		resp.SoftwareVersion = reg.SoftwareVersion
	}

	return resp
}

// extractClientIDFromPath extracts the client_id from the request path.
// Expected format: /register/{client_id}
func extractClientIDFromPath(path string) string {
	// Remove trailing slash
	path = strings.TrimSuffix(path, "/")
	// Find the last slash
	idx := strings.LastIndex(path, "/")
	if idx == -1 {
		return ""
	}
	clientID := path[idx+1:]
	if clientID == "" || clientID == "register" {
		return ""
	}
	return clientID
}

// writeError writes an RFC 7591-compliant error response.
func (e *ClientConfigurationEndpoint) writeError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

// ClientConfigurationResponse is the response structure for RFC 7592 operations.
type ClientConfigurationResponse struct {
	ClientID                string    `json:"client_id"`
	ClientSecret            string    `json:"client_secret,omitempty"`
	ClientIDIssuedAt        time.Time `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64     `json:"client_secret_expires_at"`
	RegistrationAccessToken string    `json:"registration_access_token,omitempty"`
	RegistrationURI         string    `json:"registration_client_uri,omitempty"`

	// Client metadata fields
	RedirectURIs                []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod     string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes                  []string `json:"grant_types,omitempty"`
	ResponseTypes               []string `json:"response_types,omitempty"`
	ClientName                  string   `json:"client_name,omitempty"`
	ClientURI                   string   `json:"client_uri,omitempty"`
	LogoURI                     string   `json:"logo_uri,omitempty"`
	Scope                       string   `json:"scope,omitempty"`
	Contacts                    []string `json:"contacts,omitempty"`
	TosURI                      string   `json:"tos_uri,omitempty"`
	PolicyURI                   string   `json:"policy_uri,omitempty"`
	JwksURI                     string   `json:"jwks_uri,omitempty"`
	Jwks                        *JWKS    `json:"jwks,omitempty"`
	SoftwareID                  string   `json:"software_id,omitempty"`
	SoftwareVersion             string   `json:"software_version,omitempty"`
	SubjectType                 string   `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg    string   `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg string   `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc string   `json:"id_token_encrypted_response_enc,omitempty"`
	PostLogoutRedirectURIs      []string `json:"post_logout_redirect_uris,omitempty"`
}

// ClientConfigurationHandler returns an http.HandlerFunc for GET /register/{client_id}.
func ClientConfigurationHandler(o OpenIDProvider) http.HandlerFunc {
	storage, ok := o.Storage().(ClientRegistrationStorage)
	if !ok {
		panic("op: Storage does not implement ClientRegistrationStorage, required for DCR management")
	}
	endpoint := NewClientConfigurationEndpoint(storage, nil)
	return func(w http.ResponseWriter, r *http.Request) {
		endpoint.Handle(w, r)
	}
}

// UpdateClientConfigurationHandler returns an http.HandlerFunc for PUT /register/{client_id}.
func UpdateClientConfigurationHandler(o OpenIDProvider) http.HandlerFunc {
	storage, ok := o.Storage().(ClientRegistrationStorage)
	if !ok {
		panic("op: Storage does not implement ClientRegistrationStorage, required for DCR management")
	}
	endpoint := NewClientConfigurationEndpoint(storage, nil)
	return func(w http.ResponseWriter, r *http.Request) {
		endpoint.Handle(w, r)
	}
}

// DeleteClientConfigurationHandler returns an http.HandlerFunc for DELETE /register/{client_id}.
func DeleteClientConfigurationHandler(o OpenIDProvider) http.HandlerFunc {
	storage, ok := o.Storage().(ClientRegistrationStorage)
	if !ok {
		panic("op: Storage does not implement ClientRegistrationStorage, required for DCR management")
	}
	endpoint := NewClientConfigurationEndpoint(storage, nil)
	return func(w http.ResponseWriter, r *http.Request) {
		endpoint.Handle(w, r)
	}
}
