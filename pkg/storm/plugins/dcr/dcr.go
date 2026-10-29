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
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/shared"
)

func init() {
	storm.RegisterPlugin("dcr", storm.PriorityDCR, func(ctx *storm.PluginContext) storm.Plugin {
		return New(ctx)
	})
}

// Plugin implements the Dynamic Client Registration endpoint.
type Plugin struct {
	store             storm.DCRStore
	allowPrivateIPs   bool
	skipTLSCertVerify bool
	endpointConfigs   shared.EndpointConfigMap // endpoint configurations (optional)
}

// Config holds the dependencies for the DCR plugin.
type Config struct {
	Store             storm.DCRStore
	AllowPrivateIPs   bool
	SkipTLSCertVerify bool
	EndpointConfigs   shared.EndpointConfigMap
}

// New creates a new DCR plugin from a PluginContext.
// Returns nil if the storage does not implement DCRStore — the Engine
// treats a nil plugin as "declined" and skips registration.
func New(ctx *storm.PluginContext) *Plugin {
	store, ok := ctx.Storage.(storm.DCRStore)
	if !ok {
		return nil
	}
	return &Plugin{
		store:             store,
		allowPrivateIPs:   ctx.AllowPrivateIPs,
		skipTLSCertVerify: ctx.SkipTLSCertVerify,
		endpointConfigs:   ctx.EndpointConfigs,
	}
}

// NewWithConfig creates a new DCR plugin with explicit configuration.
// Use this when constructing the plugin outside the Engine wiring.
func NewWithConfig(cfg Config) *Plugin {
	return &Plugin{
		store:             cfg.Store,
		allowPrivateIPs:   cfg.AllowPrivateIPs,
		skipTLSCertVerify: cfg.SkipTLSCertVerify,
		endpointConfigs:   cfg.EndpointConfigs,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "dcr" }

// Register installs the /register routes.
//
// OAuth 2.0 standard endpoint: POST /register (RFC 7591 §3)
// Also supports GET and PUT for reading and updating registrations.
func (p *Plugin) Register(r chi.Router) {
	registerPath := p.getRoutePath("dcr", "/register")
	r.Post(registerPath, p.handleCreate)
	r.Get(registerPath+"/{client_id}", p.handleGet)
	r.Put(registerPath+"/{client_id}", p.handleUpdate)
	r.Delete(registerPath+"/{client_id}", p.handleDelete)
}

// Contribute returns the discovery fields for the registration endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.RegistrationEndpoint = p.resolveEndpoint(ctx, "dcr", "/register")
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

func (p *Plugin) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req storm.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error decoding request body").WithParent(err), nil)
		return
	}

	// RFC 6749 §3.1.2: redirect URIs must not contain a fragment component.
	for _, redirectURI := range req.RedirectURIs {
		if u, err := url.Parse(redirectURI); err == nil && u.Fragment != "" {
			shared.WriteError(w, r,
				protocol.ErrInvalidClientMetadata().WithDescription("redirect_uri must not contain a fragment: %s", redirectURI),
				nil)
			return
		}
	}

	// OIDC Core §4: initiate_login_uri MUST use HTTPS.
	if req.InitiateLoginURI != "" {
		if u, err := url.Parse(req.InitiateLoginURI); err != nil || u.Scheme != "https" {
			shared.WriteError(w, r,
				protocol.ErrInvalidClientMetadata().WithDescription("initiate_login_uri must use https scheme"),
				nil)
			return
		}
	}

	// OIDC Core §8.1: sector_identifier_uri validation.
	// Must be a valid HTTPS URI, fetchable, returning a JSON array of redirect_uri values.
	// All registered redirect_uris must be contained in that array.
	if req.SectorIdentifierURI != "" {
		if err := p.validateSectorIdentifierURI(req.SectorIdentifierURI, req.RedirectURIs); err != nil {
			shared.WriteError(w, r,
				protocol.ErrInvalidClientMetadata().WithDescription("invalid sector_identifier_uri: %s", err.Error()),
				nil)
			return
		}
	}

	// If jwks_uri specified but jwks not, fetch the key set and populate jwks
	// so the storage layer can parse encryption keys from it.
	if len(req.JWKS) == 0 && req.JWKSURI != "" {
		resp, err := shared.FetchRemoteURL(req.JWKSURI, p.skipTLSCertVerify, p.allowPrivateIPs)
		if err != nil {
			shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("failed to fetch jwks_uri: %s", req.JWKSURI).WithParent(err), nil)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("failed to fetch jwks_uri: HTTP %d", resp.StatusCode), nil)
			return
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("failed to read jwks_uri response").WithParent(err), nil)
			return
		}
		if !json.Valid(body) {
			shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("jwks_uri response is not valid JSON"), nil)
			return
		}
		if _, err := jwk.Parse(body); err != nil {
			shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("jwks_uri response is not a valid JWK Set").WithParent(err), nil)
			return
		}
		req.JWKS = body
	}

	// Generate client credentials
	clientID := generateClientID()
	clientSecret := generateClientSecret()
	accessToken := generateAccessToken()
	uri := shared.EndpointURL(r.Context(), protocol.NewEndpoint("/register/"+clientID))

	reg, err := p.store.CreateClient(r.Context(), &req, clientID, clientSecret, accessToken, uri)
	if err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error creating client"), nil)
		return
	}

	shared.JSONResponse(w, reg, http.StatusCreated)
}

// authenticateRegistrationToken validates the registration access token
// and ensures it matches the expected client_id.
func (p *Plugin) authenticateRegistrationToken(r *http.Request, clientID string) (*storm.ClientRegistration, error) {
	token := shared.ExtractBearerToken(r)
	if token == "" {
		return nil, protocol.ErrInvalidClient().WithDescription("registration access token required")
	}

	reg, err := p.store.GetClientRegistrationByToken(r.Context(), token)
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithParent(err)
	}

	if reg.ClientID != clientID {
		return nil, protocol.ErrInvalidClient().WithDescription("client_id mismatch")
	}

	return reg, nil
}

func (p *Plugin) handleGet(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")

	reg, err := p.authenticateRegistrationToken(r, clientID)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	shared.JSONResponse(w, reg, http.StatusOK)
}

func (p *Plugin) handleUpdate(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")

	if _, err := p.authenticateRegistrationToken(r, clientID); err != nil {
		shared.WriteError(w, r, err, nil)
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

	if _, err := p.authenticateRegistrationToken(r, clientID); err != nil {
		shared.WriteError(w, r, err, nil)
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
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// validateSectorIdentifierURI implements OIDC Core §8.1 validation.
// The sector_identifier_uri must be a valid HTTPS URL, fetchable, returning
// a JSON array of redirect_uri values. All registered redirect_uris must be
// contained in that array.
func (p *Plugin) validateSectorIdentifierURI(sectorURI string, redirectURIs []string) error {
	u, err := url.Parse(sectorURI)
	if err != nil || u.Scheme != "https" {
		return fmt.Errorf("sector_identifier_uri must use https scheme")
	}

	resp, err := shared.FetchRemoteURL(sectorURI, p.skipTLSCertVerify, p.allowPrivateIPs)
	if err != nil {
		return fmt.Errorf("failed to fetch sector_identifier_uri: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sector_identifier_uri returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read sector_identifier_uri response: %w", err)
	}

	var allowedURIs []string
	if err := json.Unmarshal(body, &allowedURIs); err != nil {
		return fmt.Errorf("sector_identifier_uri response is not a JSON array of strings")
	}

	allowedSet := make(map[string]struct{}, len(allowedURIs))
	for _, u := range allowedURIs {
		allowedSet[u] = struct{}{}
	}
	for _, redirectURI := range redirectURIs {
		if _, ok := allowedSet[redirectURI]; !ok {
			return fmt.Errorf("redirect_uri %q is not listed in sector_identifier_uri response", redirectURI)
		}
	}
	return nil
}
