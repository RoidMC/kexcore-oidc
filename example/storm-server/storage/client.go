// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package storage

import (
	"time"

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
	clientEncryptionKey            interface{} // public key for ID token encryption (RSA, ECDH, or symmetric)
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
func (c *Client) IDTokenUserinfoClaimsAssertion() bool   { return c.idTokenUserinfoClaimsAssertion }
func (c *Client) IsScopeAllowed(scope string) bool       { return scope == CustomScope }
func (c *Client) IDTokenEncryptionAlg() string           { return c.idTokenEncryptionAlg }
func (c *Client) IDTokenEncryptionEnc() string           { return c.idTokenEncryptionEnc }
func (c *Client) BackChannelLogoutURI() string           { return c.backChannelLogoutURI }
func (c *Client) ClientEncryptionKey() interface{}       { return c.clientEncryptionKey }

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
	c.postLogoutRedirectURIs = []string{
		"https://www.certification.openid.net/test/a/kexcore-test/post_logout_redirect",
	}
	return c
}

func OIDFTestClientSecretPost(id, secret string, redirectURIs ...string) *Client {
	c := OIDFTestClient(id, secret, redirectURIs...)
	c.authMethod = protocol.AuthMethodPost
	return c
}

func OIDFBackChannelLogoutTestClient(id, secret, backChannelLogoutURI string, redirectURIs ...string) *Client {
	c := OIDFTestClient(id, secret, redirectURIs...)
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
		grantTypes:    []protocol.GrantType{protocol.GrantTypeDeviceCode},
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
