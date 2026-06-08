// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package client

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	httphelper "github.com/roidmc/kexcore-oidc/pkg/util/http"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// Endpoints holds all OAuth2/OIDC endpoints discovered from an issuer.
// This is shared between RP and RS to avoid duplication.
type Endpoints struct {
	// OAuth2 endpoints
	AuthURL  string
	TokenURL string

	// OIDC endpoints
	IntrospectionURL       string
	UserinfoURL            string
	JWKSURL                string
	EndSessionURL          string
	RevocationURL          string
	DeviceAuthorizationURL string
	PushedAuthRequestURL   string

	// AuthStyle for token endpoint
	AuthStyle oauth2.AuthStyle
}

// GetEndpoints extracts all endpoints from a discovery configuration.
func GetEndpoints(config *protocol.DiscoveryConfiguration) Endpoints {
	return Endpoints{
		AuthURL:                config.AuthorizationEndpoint,
		TokenURL:               config.TokenEndpoint,
		IntrospectionURL:       config.IntrospectionEndpoint,
		UserinfoURL:            config.UserinfoEndpoint,
		JWKSURL:                config.JWKSURI,
		EndSessionURL:          config.EndSessionEndpoint,
		RevocationURL:          config.RevocationEndpoint,
		DeviceAuthorizationURL: config.DeviceAuthorizationEndpoint,
		PushedAuthRequestURL:   config.PushedAuthorizationRequestEndpoint,
		AuthStyle:              oauth2.AuthStyleAutoDetect,
	}
}

// ClientAuthMethod represents the client authentication method.
type ClientAuthMethod int

const (
	ClientAuthNone ClientAuthMethod = iota
	ClientAuthBasic
	ClientAuthJWTProfile
)

// ClientCredentialsBuilder helps construct client credentials requests.
// It is used by both RP and RS to avoid code duplication.
type ClientCredentialsBuilder struct {
	ClientID     string
	ClientSecret string
	Signer       *crypto.Signer
	Issuer       string
	Scopes       []string
}

// NewClientCredentialsBuilder creates a new builder for client credentials.
func NewClientCredentialsBuilder(clientID, clientSecret string) *ClientCredentialsBuilder {
	return &ClientCredentialsBuilder{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

// WithSigner sets the JWT profile signer for private_key_jwt authentication.
func (b *ClientCredentialsBuilder) WithSigner(signer *crypto.Signer, issuer string) *ClientCredentialsBuilder {
	b.Signer = signer
	b.Issuer = issuer
	return b
}

// WithScopes sets the requested scopes.
func (b *ClientCredentialsBuilder) WithScopes(scopes ...string) *ClientCredentialsBuilder {
	b.Scopes = scopes
	return b
}

// Build creates the ClientCredentialsRequest.
// If a signer is set, it will use JWT Profile assertion authentication.
// Otherwise, it uses client_secret_basic authentication.
func (b *ClientCredentialsBuilder) Build() (*protocol.ClientCredentialsRequest, error) {
	req := &protocol.ClientCredentialsRequest{
		GrantType:    protocol.GrantTypeClientCredentials,
		Scope:        b.Scopes,
		ClientID:     b.ClientID,
		ClientSecret: b.ClientSecret,
	}

	if b.Signer != nil {
		assertion, err := SignedJWTProfileAssertion(
			b.ClientID,
			[]string{b.Issuer},
			time.Hour,
			b.Signer,
		)
		if err != nil {
			return nil, err
		}
		req.ClientAssertion = assertion
		req.ClientAssertionType = protocol.ClientAssertionTypeJWTAssertion
	}

	return req, nil
}

// ClientCredentials performs the client credentials grant flow.
// This is a shared implementation used by both RP and RS.
func ClientCredentials(ctx context.Context, tokenURL string, req *protocol.ClientCredentialsRequest, httpClient *http.Client) (*oauth2.Token, error) {
	ctx, span := Tracer.Start(ctx, "ClientCredentials")
	defer span.End()

	config := &oauth2.Config{
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		Scopes:       req.Scope,
		Endpoint: oauth2.Endpoint{
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
	}

	var opts []oauth2.AuthCodeOption
	if req.ClientAssertion != "" {
		opts = append(opts,
			oauth2.SetAuthURLParam("client_assertion", req.ClientAssertion),
			oauth2.SetAuthURLParam("client_assertion_type", req.ClientAssertionType),
		)
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	token, err := config.TokenSource(ctx, &oauth2.Token{}).Token()
	if err != nil {
		return nil, err
	}

	return token, nil
}

// BaseClient provides common functionality for both RP and RS.
// It handles discovery, endpoint management, and HTTP client configuration.
type BaseClient struct {
	Issuer     string
	Endpoints  Endpoints
	HTTPClient *http.Client
}

// NewBaseClient creates a base client with the given issuer and HTTP client.
func NewBaseClient(issuer string, httpClient *http.Client) *BaseClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &BaseClient{
		Issuer:     issuer,
		HTTPClient: httpClient,
	}
}

// Discover performs OIDC discovery and populates the endpoints.
func (c *BaseClient) Discover(ctx context.Context, wellKnownURL ...string) error {
	config, err := Discover(ctx, c.Issuer, c.HTTPClient, wellKnownURL...)
	if err != nil {
		return err
	}
	c.Endpoints = GetEndpoints(config)
	return nil
}

// IntrospectionCaller is the interface for calling the introspection endpoint.
// Both RP and RS can implement this interface.
type IntrospectionCaller interface {
	IntrospectionURL() string
	HttpClient() *http.Client
}

// CallIntrospectionEndpoint calls the RFC 7662 token introspection endpoint.
func CallIntrospectionEndpoint(ctx context.Context, token string, caller IntrospectionCaller, authFn any) (*protocol.IntrospectionResponse, error) {
	ctx, span := Tracer.Start(ctx, "CallIntrospectionEndpoint")
	defer span.End()

	if caller.IntrospectionURL() == "" {
		return nil, ErrEndpointNotSet
	}

	req, err := httphelper.FormRequest(ctx, caller.IntrospectionURL(), &protocol.IntrospectionRequest{Token: token}, Encoder, authFn)
	if err != nil {
		return nil, err
	}

	resp := new(protocol.IntrospectionResponse)
	if err := httphelper.HttpRequest(caller.HttpClient(), req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}
