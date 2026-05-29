// Package discovery implements the OIDC Discovery document plugin.
//
// This plugin contributes the standard discovery fields (token_endpoint,
// userinfo_endpoint, etc.) and serves them via the Engine's discovery
// aggregator. It does not register any standalone routes.
package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin is the Discovery contributor plugin.
// It provides the standard OIDC discovery fields based on the Engine's
// issuer and the configured endpoints.
type Plugin struct {
	endpoints Endpoints
	keyStore  storm.KeyStore
	config    Config
}

// Endpoints defines the URLs exposed by the OIDC server.
type Endpoints struct {
	Authorization       string
	Token               string
	Introspection       string
	Userinfo            string
	Revocation          string
	EndSession          string
	CheckSession        string
	DeviceAuthorization string
	PushedAuthRequest   string
	BackChannelLogout   string
	FrontChannelLogout  string
	Registration        string
	TokenExchange       string
	Keys                string
}

// Config holds optional overrides for the discovery document.
// OAuth 2.1 compliant defaults are used when fields are empty.
type Config struct {
	// GrantTypes overrides grant_types_supported.
	// Default (OAuth 2.1): authorization_code, client_credentials, refresh_token,
	//   urn:ietf:params:oauth:grant-type:jwt-bearer,
	//   urn:ietf:params:oauth:grant-type:token-exchange,
	//   urn:ietf:params:oauth:grant-type:device_code
	GrantTypes []string

	// ResponseTypes overrides response_types_supported.
	// Default (OAuth 2.1): code
	ResponseTypes []string

	// ExtraFields are additional key-value pairs merged into the document.
	ExtraFields map[string]any
}

// DefaultGrantTypes returns the OAuth 2.1 default grant types.
func DefaultGrantTypes() []string {
	return []string{
		"authorization_code",
		"client_credentials",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:token-exchange",
		"urn:ietf:params:oauth:grant-type:device_code",
	}
}

// DefaultResponseTypes returns the OAuth 2.1 default response types.
func DefaultResponseTypes() []string {
	return []string{"code"}
}

// New creates a new Discovery plugin.
// If keyStore is non-nil, the discovery document will include the
// signing algorithms declared by the key store (including GM/T algorithms).
func New(endpoints Endpoints, keyStore storm.KeyStore, cfg ...Config) *Plugin {
	var config Config
	if len(cfg) > 0 {
		config = cfg[0]
	}
	return &Plugin{endpoints: endpoints, keyStore: keyStore, config: config}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "discovery" }

// Register is a no-op for the Discovery plugin.
// All discovery logic is handled by the Engine's aggregator.
func (p *Plugin) Register(r chi.Router) {}

// Contribute returns the standard OIDC discovery fields.
// The issuer is injected by the Engine via the request context.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	issuer := shared.IssuerFromContext(ctx)

	idTokenSigningAlgs := []string{"RS256"}
	tokenEndpointAuthSigningAlgs := []string{"RS256", "ES256"}
	if p.keyStore != nil {
		if algs, err := p.keyStore.SignatureAlgorithms(ctx); err == nil && len(algs) > 0 {
			idTokenSigningAlgs = algs
			tokenEndpointAuthSigningAlgs = algs
		}
	}

	grantTypes := p.config.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = DefaultGrantTypes()
	}
	responseTypes := p.config.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = DefaultResponseTypes()
	}

	cfg := map[string]any{
		"authorization_endpoint":                           makeURL(issuer, p.endpoints.Authorization),
		"token_endpoint":                                   makeURL(issuer, p.endpoints.Token),
		"introspection_endpoint":                           makeURL(issuer, p.endpoints.Introspection),
		"userinfo_endpoint":                                makeURL(issuer, p.endpoints.Userinfo),
		"revocation_endpoint":                              makeURL(issuer, p.endpoints.Revocation),
		"end_session_endpoint":                             makeURL(issuer, p.endpoints.EndSession),
		"check_session_iframe":                             makeURL(issuer, p.endpoints.CheckSession),
		"device_authorization_endpoint":                    makeURL(issuer, p.endpoints.DeviceAuthorization),
		"pushed_authorization_request_endpoint":            makeURL(issuer, p.endpoints.PushedAuthRequest),
		"backchannel_logout_endpoint":                           makeURL(issuer, p.endpoints.BackChannelLogout),
		"frontchannel_logout_endpoint":                          makeURL(issuer, p.endpoints.FrontChannelLogout),
		"registration_endpoint":                            makeURL(issuer, p.endpoints.Registration),
		"token_exchange_endpoint":                          makeURL(issuer, p.endpoints.TokenExchange),
		"jwks_uri":                                         makeURL(issuer, p.endpoints.Keys),
		"scopes_supported":                                 []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		"response_types_supported":                         responseTypes,
		"grant_types_supported":                            grantTypes,
		"subject_types_supported":                          []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported":            idTokenSigningAlgs,
		"token_endpoint_auth_methods_supported":            []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": tokenEndpointAuthSigningAlgs,
		"claims_supported":                                 []string{"sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "c_hash", "at_hash", "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "phone_number", "phone_number_verified", "address", "updated_at"},
		"code_challenge_methods_supported":                 []string{"S256"},
		"request_uri_parameter_supported":                  true,
		"require_request_uri_registration":                 false,
	}

	for k, v := range p.config.ExtraFields {
		cfg[k] = v
	}

	return cfg
}

func makeURL(issuer, path string) string {
	if path == "" {
		return ""
	}
	issuer = strings.TrimRight(issuer, "/")
	if len(path) > 0 && path[0] == '/' {
		return issuer + path
	}
	return fmt.Sprintf("%s/%s", issuer, path)
}
