// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios
//
// Dynamic Client Registration (RFC 7591) endpoint implementation.
//
// This endpoint implements RFC 7591 Section 3 - Client Registration Endpoint.
// The endpoint is protected and requires an initial access token
// (not open/public registration).

package op

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultClientRegistrationEndpoint is the default path for the DCR endpoint.
	DefaultClientRegistrationEndpoint = "/register"

	// DefaultClientRegistrationExpiration is how long the registration access token
	// is valid for management operations (RFC 7592).
	DefaultClientRegistrationExpiration = 24 * time.Hour

	// ClientSecretExpiration indicates that the client secret does not expire.
	ClientSecretExpiration = 0
)

// RegistrationConfig holds configuration for the DCR endpoint.
type RegistrationConfig struct {
	// RegistrationEndpoint is the path for the /register endpoint.
	// Default: /register
	RegistrationEndpoint string

	// AccessTokenRequired forces clients to present an initial access token.
	// When true, the registration endpoint will require a valid initial access
	// token (Bearer auth).
	AccessTokenRequired bool

	// SecretExpiration is the duration after which client secrets expire.
	// A value of 0 means secrets never expire.
	SecretExpiration time.Duration
}

// DefaultRegistrationConfig returns the default DCR configuration.
// By default, the registration endpoint requires authentication
// (not open/public registration).
func DefaultRegistrationConfig() *RegistrationConfig {
	return &RegistrationConfig{
		RegistrationEndpoint: DefaultClientRegistrationEndpoint,
		AccessTokenRequired:  true,
		SecretExpiration:     0, // secrets never expire by default
	}
}

// RegisterClientEndpoint handles POST /register (RFC 7591 Section 3.1)
// and GET /register/:clientID (RFC 7592 Section 2) requests.
type RegisterClientEndpoint struct {
	Storage ClientRegistrationStorage
	Config  *RegistrationConfig
	Logger  *slog.Logger
}

// NewRegisterClientEndpoint creates a new DCR endpoint handler.
func NewRegisterClientEndpoint(storage ClientRegistrationStorage, config *RegistrationConfig, logger *slog.Logger) *RegisterClientEndpoint {
	if config == nil {
		config = DefaultRegistrationConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RegisterClientEndpoint{
		Storage: storage,
		Config:  config,
		Logger:  logger,
	}
}

// Handle handles the registration endpoint based on the HTTP method.
func (e *RegisterClientEndpoint) Handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		e.registerClient(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// registerClient handles POST /register (RFC 7591 Section 3.1 - Client Registration Request).
func (e *RegisterClientEndpoint) registerClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate the initial access token (RFC 7591 Section 3.2.2)
	if err := e.authenticateInitialAccess(r); err != nil {
		e.Logger.Warn("dcr: initial access token validation failed", "error", err)
		// Per RFC 6750 (Bearer Token Usage), authentication errors should use invalid_token
		e.writeError(w, http.StatusUnauthorized, "invalid_token",
			"valid initial access token is required for client registration")
		return
	}

	// Parse the registration request body
	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		e.writeError(w, http.StatusBadRequest, "invalid_client_metadata",
			"request body must be a valid JSON object")
		return
	}

	// Validate the registration request (RFC 7591 Section 3.1)
	if err := e.validateRegistrationRequest(&req); err != nil {
		e.writeError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	// Generate client credentials
	clientID, err := generateSecureToken(DefaultClientIDLength)
	if err != nil {
		e.Logger.Error("dcr: failed to generate client ID", "error", err)
		e.writeError(w, http.StatusInternalServerError, "server_error", "internal server error")
		return
	}

	var clientSecret string
	// Determine the effective auth method (default to client_secret_basic per RFC 7591)
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	if authMethod != "none" {
		clientSecret, err = generateSecureToken(DefaultSecretLength)
		if err != nil {
			e.Logger.Error("dcr: failed to generate client secret", "error", err)
			e.writeError(w, http.StatusInternalServerError, "server_error", "internal server error")
			return
		}
	}

	// Generate registration access token for management (RFC 7592)
	registrationAccessToken, err := generateSecureToken(DefaultRegistrationTokenLength)
	if err != nil {
		e.Logger.Error("dcr: failed to generate registration access token", "error", err)
		e.writeError(w, http.StatusInternalServerError, "server_error", "internal server error")
		return
	}

	// Build the registration URI (RFC 7592 Section 3)
	issuer := IssuerFromContext(r.Context())
	registrationURI := strings.TrimSuffix(issuer, "/") + e.Config.RegistrationEndpoint + "/" + clientID

	// Store the client registration
	clientRegistration, err := e.Storage.CreateClient(r.Context(), &req, clientID, clientSecret, registrationAccessToken, registrationURI)
	if err != nil {
		e.Logger.Error("dcr: failed to store client registration", "error", err)
		e.writeError(w, http.StatusInternalServerError, "server_error", "internal server error")
		return
	}

	// Build the response (RFC 7591 Section 3.2)
	resp := e.buildRegistrationResponse(clientRegistration)
	if clientSecret != "" {
		resp.ClientSecret = clientSecret
		// client_secret_expires_at is REQUIRED when client_secret is returned (RFC 7591 Section 3.2.1)
		// Per RFC 7591, this is a JSON number (seconds since epoch)
		// A value of 0 means the secret never expires
		if e.Config.SecretExpiration > 0 {
			resp.ClientSecretExpiresAt = time.Now().Add(e.Config.SecretExpiration).Unix()
		}
		// If SecretExpiration == 0, ClientSecretExpiresAt remains 0 (never expires)
	}
	resp.RegistrationAccessToken = registrationAccessToken
	resp.RegistrationURI = registrationURI
	resp.ClientIDIssuedAt = time.Now()

	e.Logger.Info("dcr: client registered successfully", "client_id", clientID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		e.Logger.Error("dcr: failed to encode registration response", "error", err)
	}
}

// authenticateInitialAccess validates the initial access token (if required).
func (e *RegisterClientEndpoint) authenticateInitialAccess(r *http.Request) error {
	if !e.Config.AccessTokenRequired {
		return nil
	}

	auth := r.Header.Get("Authorization")
	if auth == "" {
		return fmt.Errorf("authorization header is required for client registration")
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		return fmt.Errorf("authorization header must be Bearer token")
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "" {
		return fmt.Errorf("bearer token is required")
	}

	return e.Storage.ValidateInitialAccessToken(r.Context(), token)
}

// validateRegistrationRequest validates the registration request fields
// according to RFC 7591 Section 3.1.
func (e *RegisterClientEndpoint) validateRegistrationRequest(req *RegistrationRequest) error {
	// redirect_uris is REQUIRED when response_type includes code or token
	if len(req.RedirectURIs) == 0 && req.ContainsGrantOrResponseType("authorization_code", "implicit") {
		return fmt.Errorf("redirect_uris is required for authorization_code and implicit grant types")
	}

	// At least one redirect URI must be valid
	for _, uri := range req.RedirectURIs {
		if uri == "" {
			return fmt.Errorf("redirect_uris must not contain empty strings")
		}
		// Basic check: must be a valid URI
		if !strings.Contains(uri, "://") {
			return fmt.Errorf("invalid redirect_uri: %s", uri)
		}
	}

	// Validate token_endpoint_auth_method
	switch req.TokenEndpointAuthMethod {
	case "", "none", "client_secret_basic", "client_secret_post", "private_key_jwt": // valid
	default:
		return fmt.Errorf("unsupported token_endpoint_auth_method: %s", req.TokenEndpointAuthMethod)
	}

	// If jwks and jwks_uri are both provided, it's an error (RFC 7591 Section 2)
	if req.Jwks != nil && req.JwksURI != "" {
		return fmt.Errorf("jwks and jwks_uri must not be specified together")
	}

	return nil
}

// buildRegistrationResponse creates the response from a stored client registration.
func (e *RegisterClientEndpoint) buildRegistrationResponse(cr *ClientRegistration) *ClientRegistrationResponse {
	resp := &ClientRegistrationResponse{}

	// Propagate metadata
	resp.ClientID = cr.ClientID
	if cr.RegistrationRequest != nil {
		resp.RedirectURIs = cr.RedirectURIs
		resp.TokenEndpointAuthMethod = cr.TokenEndpointAuthMethod
		resp.GrantTypes = cr.GrantTypes
		resp.ResponseTypes = cr.ResponseTypes
		resp.ClientName = cr.ClientName
		resp.ClientURI = cr.ClientURI
		resp.LogoURI = cr.LogoURI
		resp.Scope = cr.Scope
		resp.Contacts = cr.Contacts
		resp.TosURI = cr.TosURI
		resp.PolicyURI = cr.PolicyURI
		resp.JwksURI = cr.JwksURI
		resp.Jwks = cr.Jwks
		resp.SoftwareID = cr.SoftwareID
		resp.SoftwareVersion = cr.SoftwareVersion
		resp.BackChannelLogoutURI = cr.BackChannelLogoutURI
	}

	// Propagate client_secret_expires_at from stored registration
	// (this will be 0 if the secret never expires, per RFC 7591 Section 3.2.1)
	resp.ClientSecretExpiresAt = cr.ClientSecretExpiresAt

	return resp
}

// writeError writes an RFC 7591-compliant error response.
// For 401 Unauthorized responses, it also sets the WWW-Authenticate header
// as required by RFC 6750 Section 3.
func (e *RegisterClientEndpoint) writeError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		// Per RFC 6750 Section 3, WWW-Authenticate is required for 401
		// The realm is set to the issuer if available
		realm := ""
		if e.Config != nil && e.Config.RegistrationEndpoint != "" {
			realm = fmt.Sprintf(`realm="%s"`, e.Config.RegistrationEndpoint)
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer %s, error="%s", error_description="%s"`, realm, errorCode, description))
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

// ClientRegistrationResponse is the response structure returned to the client
// after successful registration (RFC 7591 Section 3.2).
type ClientRegistrationResponse struct {
	ClientID                string    `json:"client_id"`
	ClientSecret            string    `json:"client_secret,omitempty"`
	ClientIDIssuedAt        time.Time `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64     `json:"client_secret_expires_at"`
	RegistrationAccessToken string    `json:"registration_access_token,omitempty"`
	RegistrationURI         string    `json:"registration_client_uri,omitempty"`

	// Echoed back client metadata
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	Jwks                    *JWKS    `json:"jwks,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	BackChannelLogoutURI    string   `json:"backchannel_logout_uri,omitempty"`
}

// ContainsGrantOrResponseType checks if the registration request contains
// any of the specified grant types or response types.
// If no grant_types are specified in the request, the default grant type
// (authorization_code) is assumed per RFC 7591 Section 2.1.
// If no response_types are specified, the default response type (code) is assumed.
func (r *RegistrationRequest) ContainsGrantOrResponseType(types ...string) bool {
	grantTypes := r.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	responseTypes := r.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	for _, t := range types {
		for _, gt := range grantTypes {
			if gt == t {
				return true
			}
		}
		for _, rt := range responseTypes {
			if rt == t {
				return true
			}
		}
	}
	return false
}

// generateSecureToken generates a cryptographically random hex token.
func generateSecureToken(byteLength int) (string, error) {
	token := make([]byte, byteLength)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(token), nil
}

// RegistrationProvider is an optional interface that can be implemented by
// the Provider to indicate support for Dynamic Client Registration.
type RegistrationProvider interface {
	ClientRegistrationStorage() ClientRegistrationStorage
}

// RegisterClientHandler returns an http.HandlerFunc for the POST /register endpoint.
func RegisterClientHandler(o OpenIDProvider) http.HandlerFunc {
	storage, ok := o.Storage().(ClientRegistrationStorage)
	if !ok {
		panic("op: Storage does not implement ClientRegistrationStorage, required for DCR support")
	}
	endpoint := NewRegisterClientEndpoint(storage, nil, nil)
	return func(w http.ResponseWriter, r *http.Request) {
		endpoint.Handle(w, r)
	}
}

// DCRHandler returns an http.Handler for Dynamic Client Registration.
// It can be mounted on any router to add DCR support.
func DCRHandler(storage ClientRegistrationStorage, config *RegistrationConfig, logger *slog.Logger) http.Handler {
	endpoint := NewRegisterClientEndpoint(storage, config, logger)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint.Handle(w, r)
	})
}
