// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package storage

import (
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

var (
	defaultLoginURL = func(id string) string {
		return "/login/username?authRequestID=" + id
	}
)

// Client represents an OAuth/OIDC client.
// It implements storm.Client and various optional interfaces
// checked via type assertions by plugins.
type Client struct {
	id                             string
	secret                         string
	redirectURIs                   []string
	appType                        int // 0=web, 1=native, 2=useragent
	authMethod                     protocol.AuthMethod
	loginURLFn                     func(string) string
	responseTypes                  []protocol.ResponseType
	grantTypes                     []protocol.GrantType
	devMode                        bool
	idTokenUserinfoClaimsAssertion bool
	clockSkew                      time.Duration
	postLogoutRedirectURIs         []string
	idTokenEncryptionAlg           string
	idTokenEncryptionEnc           string
	backChannelLogoutURI           string
	logoURI                        string
	policyURI                      string
	tosURI                         string
	sectorIdentifierURI            string
	clientEncryptionKey            interface{} // public key for ID token encryption (RSA, ECDH, or symmetric)
	clientJWKS                     []jwk.Key   // client's public keys for JWT bearer grant verification
	jwksURI                        string      // client's jwks_uri for fetching fresh keys
	userInfoSignedResponseAlg      string      // userinfo_signed_response_alg from DCR
	idTokenSignedResponseAlg       string      // id_token_signed_response_alg from DCR
	requestObjectSigningAlg        string      // request_object_signing_alg (e.g. "PS256" for FAPI 2.0 signed_non_repudiation)
	fapiProfile                    bool        // FAPI 2.0 profile restrictions
	requireDPoP                    bool        // require DPoP proof at token endpoint
	requireMtls                    bool        // require mTLS client auth at token endpoint
}

func (c *Client) GetID() string                          { return c.id }
func (c *Client) AuthMethod() protocol.AuthMethod        { return c.authMethod }
func (c *Client) LoginURL(id string) string              { return c.loginURLFn(id) }
func (c *Client) RedirectURIs() []string                 { return c.redirectURIs }
func (c *Client) PostLogoutRedirectURIs() []string       { return c.postLogoutRedirectURIs }
func (c *Client) ResponseTypes() []protocol.ResponseType { return c.responseTypes }
func (c *Client) GrantTypes() []protocol.GrantType       { return c.grantTypes }
func (c *Client) DevMode() bool                          { return c.devMode }
func (c *Client) IDTokenLifetime() time.Duration         { return 1 * time.Hour }
func (c *Client) ClockSkew() time.Duration               { return c.clockSkew }
func (c *Client) FAPIProfile() bool                      { return c.fapiProfile }
func (c *Client) IDTokenUserinfoClaimsAssertion() bool   { return c.idTokenUserinfoClaimsAssertion }
func (c *Client) IsScopeAllowed(scope string) bool       { return scope == CustomScope }
func (c *Client) IDTokenEncryptionAlg() string           { return c.idTokenEncryptionAlg }
func (c *Client) IDTokenEncryptionEnc() string           { return c.idTokenEncryptionEnc }
func (c *Client) BackChannelLogoutURI() string           { return c.backChannelLogoutURI }
func (c *Client) LogoURI() string                        { return c.logoURI }
func (c *Client) PolicyURI() string                      { return c.policyURI }
func (c *Client) TOSURI() string                         { return c.tosURI }
func (c *Client) ClientEncryptionKey() interface{}       { return c.clientEncryptionKey }
func (c *Client) ClientJWKS() []jwk.Key                  { return c.clientJWKS }
func (c *Client) ClientJWKSURI() string                  { return c.jwksURI }
func (c *Client) RequestObjectSigningAlg() string        { return c.requestObjectSigningAlg }
func (c *Client) RequireDPoP() bool                      { return c.requireDPoP }
func (c *Client) RequireMtls() bool                      { return c.requireMtls }
func (c *Client) IDTokenSignedResponseAlg() string       { return c.idTokenSignedResponseAlg }

// WithRequestObjectSigningAlg sets the request_object_signing_alg for this client
// and returns the client for chaining. Use "PS256" for FAPI 2.0 signed_non_repudiation.
func (c *Client) WithRequestObjectSigningAlg(alg string) *Client {
	c.requestObjectSigningAlg = alg
	return c
}

// WithRequireDPoP enables DPoP sender-constraining for this client.
func (c *Client) WithRequireDPoP() *Client {
	c.requireDPoP = true
	return c
}

// WithRequireMtls enables mTLS sender-constraining for this client.
func (c *Client) WithRequireMtls() *Client {
	c.requireMtls = true
	return c
}

// WithIDTokenSignedResponseAlg sets the id_token_signed_response_alg for this client.
func (c *Client) WithIDTokenSignedResponseAlg(alg string) *Client {
	c.idTokenSignedResponseAlg = alg
	return c
}

func (s *Storage) RegisterClients(registerClients ...*Client) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, c := range registerClients {
		s.clients[c.id] = c
	}
}

func NativeClient(id string, redirectURIs ...string) *Client {
	if len(redirectURIs) == 0 {
		redirectURIs = []string{"http://localhost/auth/callback", "custom://auth/callback"}
	}
	return &Client{
		id:            id,
		authMethod:    protocol.AuthMethodNone,
		redirectURIs:  redirectURIs,
		appType:       1,
		loginURLFn:    defaultLoginURL,
		responseTypes: []protocol.ResponseType{protocol.ResponseTypeCode},
		grantTypes:    []protocol.GrantType{protocol.GrantTypeCode, protocol.GrantTypeRefreshToken},
	}
}

func WebClient(id, secret string, redirectURIs ...string) *Client {
	if len(redirectURIs) == 0 {
		redirectURIs = []string{"http://localhost:9999/auth/callback"}
	}
	return &Client{
		id:           id,
		secret:       secret,
		redirectURIs: redirectURIs,
		appType:      0,
		authMethod:   protocol.AuthMethodBasic,
		loginURLFn:   defaultLoginURL,
		responseTypes: []protocol.ResponseType{
			protocol.ResponseTypeCode,
			protocol.ResponseTypeIDTokenOnly,
			protocol.ResponseTypeIDToken,
			protocol.ResponseTypeCodeIDToken,
			protocol.ResponseTypeCodeToken,
			protocol.ResponseTypeCodeIDTokenToken,
		},
		grantTypes: []protocol.GrantType{protocol.GrantTypeCode, protocol.GrantTypeRefreshToken, protocol.GrantTypeClientCredentials, protocol.GrantTypeTokenExchange},
		devMode:    true,
	}
}

func OIDFTestClient(id, secret string, redirectURIs ...string) *Client {
	c := WebClient(id, secret, redirectURIs...)
	// Derive post_logout_redirect_uri from the first redirect URI (same host as conformance suite)
	for _, uri := range redirectURIs {
		if u, err := url.Parse(uri); err == nil {
			c.postLogoutRedirectURIs = append(c.postLogoutRedirectURIs,
				u.Scheme+"://"+u.Host+"/test/a/kexcore-test/post_logout_redirect")
			break
		}
	}
	// Always include the official certification URL
	c.postLogoutRedirectURIs = append(c.postLogoutRedirectURIs,
		"https://www.certification.openid.net/test/a/kexcore-test/post_logout_redirect")
	// FAPI 2.0 security profile: enable both DPoP and mTLS sender-constraining
	// by default. The actual holder-of-key mechanism used is determined by the
	// client's request (DPoP proof vs mTLS certificate) and the conformance
	// variant under test.
	c.requireDPoP = true
	c.requireMtls = true
	return c
}

func OIDFTestClientSecretPost(id, secret string, redirectURIs ...string) *Client {
	c := OIDFTestClient(id, secret, redirectURIs...)
	c.authMethod = protocol.AuthMethodPost
	return c
}

func OIDFBackChannelLogoutTestClient(id, secret, backChannelLogoutURI string, redirectURIs ...string) *Client {
	c := OIDFTestClientSecretPost(id, secret, redirectURIs...)
	c.backChannelLogoutURI = backChannelLogoutURI
	return c
}

// OIDFBackChannelLogoutEncryptedTestClient creates an OIDF test client with
// back-channel logout and ID token encryption support.
func OIDFBackChannelLogoutEncryptedTestClient(id, secret, backChannelLogoutURI, alg, enc string, key interface{}, redirectURIs ...string) *Client {
	c := OIDFTestClient(id, secret, redirectURIs...)
	c.backChannelLogoutURI = backChannelLogoutURI
	c.idTokenEncryptionAlg = alg
	c.idTokenEncryptionEnc = enc
	c.clientEncryptionKey = key
	return c
}

func DeviceClient(id, secret string) *Client {
	return &Client{
		id:            id,
		secret:        secret,
		authMethod:    protocol.AuthMethodBasic,
		loginURLFn:    defaultLoginURL,
		responseTypes: []protocol.ResponseType{protocol.ResponseTypeCode},
		grantTypes:    []protocol.GrantType{protocol.GrantTypeDeviceCode, protocol.GrantTypeRefreshToken},
	}
}

func EncryptedWebClient(id, secret string, alg, enc string, redirectURIs ...string) *Client {
	c := WebClient(id, secret, redirectURIs...)
	c.idTokenEncryptionAlg = alg
	c.idTokenEncryptionEnc = enc
	return c
}

// EncryptedWebClientWithKey creates a web client with ID token encryption
// using the provided public key (RSA, ECDH, or symmetric key).
func EncryptedWebClientWithKey(id, secret string, alg, enc string, key interface{}, redirectURIs ...string) *Client {
	c := WebClient(id, secret, redirectURIs...)
	c.idTokenEncryptionAlg = alg
	c.idTokenEncryptionEnc = enc
	c.clientEncryptionKey = key
	return c
}

func BackChannelLogoutWebClient(id, secret, uri string, redirectURIs ...string) *Client {
	c := WebClient(id, secret, redirectURIs...)
	c.backChannelLogoutURI = uri
	return c
}

// OIDFEncryptedTestClient creates an OIDF test client with ID token encryption
// using jwk.Key (which includes kid in the JWE header per OIDCC-10.2.1).
func OIDFEncryptedTestClient(id, secret string, alg, enc string, key interface{}, redirectURIs ...string) *Client {
	c := OIDFTestClient(id, secret, redirectURIs...)
	c.idTokenEncryptionAlg = alg
	c.idTokenEncryptionEnc = enc
	c.clientEncryptionKey = key
	return c
}

// FAPIClient creates a FAPI-compliant client using private_key_jwt authentication.
// The client supports authorization_code and client_credentials grants,
// and uses the provided JWK set for JWT bearer verification.
func FAPIClient(id string, clientJWKS []jwk.Key, redirectURIs ...string) *Client {
	if len(redirectURIs) == 0 {
		redirectURIs = []string{"https://192.168.2.167:8443/test/a/kexcore-test/callback"}
	}
	c := &Client{
		id:           id,
		redirectURIs: redirectURIs,
		appType:      0,
		authMethod:   protocol.AuthMethodPrivateKeyJWT,
		loginURLFn:   defaultLoginURL,
		responseTypes: []protocol.ResponseType{
			protocol.ResponseTypeCode,
			protocol.ResponseTypeIDToken,
			protocol.ResponseTypeIDTokenOnly,
			protocol.ResponseTypeCodeIDToken,
			protocol.ResponseTypeCodeToken,
			protocol.ResponseTypeCodeIDTokenToken,
		},
		grantTypes: []protocol.GrantType{
			protocol.GrantTypeCode,
			protocol.GrantTypeRefreshToken,
			protocol.GrantTypeClientCredentials,
		},
		clientJWKS:               clientJWKS,
		fapiProfile:              true,
		idTokenSignedResponseAlg: "PS256",
		requestObjectSigningAlg:  "PS256",
		requireDPoP:              true,
		requireMtls:              true,
	}
	// Derive post_logout_redirect_uri from the first redirect URI
	for _, uri := range redirectURIs {
		if u, err := url.Parse(uri); err == nil {
			c.postLogoutRedirectURIs = append(c.postLogoutRedirectURIs,
				u.Scheme+"://"+u.Host+"/test/a/kexcore-test/post_logout_redirect")
			break
		}
	}
	c.postLogoutRedirectURIs = append(c.postLogoutRedirectURIs,
		"https://www.certification.openid.net/test/a/kexcore-test/post_logout_redirect")
	return c
}

// FAPIClientWithJWKSURI creates a FAPI-compliant client using private_key_jwt
// authentication with a jwks_uri for key discovery.
func FAPIClientWithJWKSURI(id, jwksURI string, redirectURIs ...string) *Client {
	c := FAPIClient(id, nil, redirectURIs...)
	c.jwksURI = jwksURI
	return c
}
