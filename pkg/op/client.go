// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package op

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	httphelper "github.com/roidmc/kexcore-oidc/pkg/http"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

//go:generate go get github.com/dmarkham/enumer
//go:generate go run github.com/dmarkham/enumer -linecomment -sql -json -text -yaml -gqlgen -type=ApplicationType,AccessTokenType
//go:generate go mod tidy

const (
	ApplicationTypeWeb       ApplicationType = iota // web
	ApplicationTypeUserAgent                        // user_agent
	ApplicationTypeNative                           // native
)

const (
	AccessTokenTypeBearer AccessTokenType = iota // bearer
	AccessTokenTypeJWT                           // JWT
)

type ApplicationType int

type AuthMethod string

type AccessTokenType int

type Client interface {
	GetID() string
	RedirectURIs() []string
	PostLogoutRedirectURIs() []string
	ApplicationType() ApplicationType
	AuthMethod() protocol.AuthMethod
	ResponseTypes() []protocol.ResponseType
	GrantTypes() []protocol.GrantType
	LoginURL(string) string
	AccessTokenType() AccessTokenType
	IDTokenLifetime() time.Duration
	DevMode() bool
	RestrictAdditionalIdTokenScopes() func(scopes []string) []string
	RestrictAdditionalAccessTokenScopes() func(scopes []string) []string
	IsScopeAllowed(scope string) bool
	IDTokenUserinfoClaimsAssertion() bool
	ClockSkew() time.Duration
}

// HasRedirectGlobs is an optional interface that can be implemented by implementors of
// Client. See https://pkg.go.dev/path#Match for glob
// interpretation. Redirect URIs that match either the non-glob version or the
// glob version will be accepted. Glob URIs are only partially supported for native
// clients: "http://" is not allowed except for loopback or in dev mode.
//
// Note that globbing / wildcards are not permitted by the OIDC
// standard and implementing this interface can have security implications.
// It is advised to only return a client of this type in rare cases,
// such as DevMode for the client being enabled.
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type HasRedirectGlobs interface {
	Client
	RedirectURIGlobs() []string
	PostLogoutRedirectURIGlobs() []string
}

// IDTokenEncryptionClient is an optional interface that clients can implement
// to request ID token encryption. When implemented, the OP will encrypt the
// signed ID token using the configured algorithm and encryption method before
// returning it in the token response.
//
// Supported algorithms:
//   - "dir" (direct encryption): The OP uses a shared symmetric key for encryption.
//     Requires Crypto to implement TokenEncryptionKeyProvider.
//   - "A256GCMKW" (AES-256 GCM Key Wrapping): Standard AES key wrapping.
//   - "SGD_SM2_3" (SM2 public-key encryption): Requires Crypto to implement
//     SM2TokenEncryptionPublicKeyProvider (GM/T 0125.3).
//   - "SGD_SM9_3" (SM9 identity-based encryption): Requires Crypto to implement
//     SM9TokenEncryptionPublicKeyProvider (GM/T 0125.3).
//
// Supported encryption methods:
//   - "SGD_SM4_GCM" (SM4-GCM, GM/T 0125.3)
//   - "A256GCM" (AES-256-GCM)
//   - "A128GCM" (AES-128-GCM)
type IDTokenEncryptionClient interface {
	Client

	// IDTokenEncryptionAlg returns the JWE algorithm for key management.
	// Returns empty string if encryption is not requested.
	IDTokenEncryptionAlg() string

	// IDTokenEncryptionEnc returns the JWE content encryption algorithm.
	// Returns empty string if encryption is not requested.
	IDTokenEncryptionEnc() string
}

// BackChannelLogoutClient is an optional interface that clients can implement
// to support back-channel logout (OpenID Connect Back-Channel Logout 1.0).
// When implemented, the OP will send a Logout Token to the client's
// backchannel_logout_uri when a session is terminated.
type BackChannelLogoutClient interface {
	Client

	// BackChannelLogoutURI returns the URI where the OP will send Logout Tokens
	// via HTTP POST when a session is terminated.
	BackChannelLogoutURI() string
}

func ContainsResponseType(types []protocol.ResponseType, responseType protocol.ResponseType) bool {
	for _, t := range types {
		if t == responseType {
			return true
		}
	}
	return false
}

func IsConfidentialType(c Client) bool {
	return c.ApplicationType() == ApplicationTypeWeb
}

var (
	ErrInvalidAuthHeader   = errors.New("invalid basic auth header")
	ErrNoClientCredentials = errors.New("no client credentials provided")
	ErrMissingClientID     = errors.New("client_id missing from request")
)

type ClientJWTProfile interface {
	JWTProfileVerifier(context.Context) *JWTProfileVerifier
}

func ClientJWTAuth(ctx context.Context, ca oidc.ClientAssertionParams, verifier ClientJWTProfile) (clientID string, err error) {
	ctx, span := Tracer.Start(ctx, "ClientJWTAuth")
	defer span.End()

	if ca.ClientAssertion == "" {
		return "", protocol.ErrInvalidClient().WithParent(ErrNoClientCredentials)
	}

	profile, err := VerifyJWTAssertion(ctx, ca.ClientAssertion, verifier.JWTProfileVerifier(ctx))
	if err != nil {
		return "", protocol.ErrUnauthorizedClient().WithParent(err).WithDescription("JWT assertion failed")
	}
	return profile.Issuer, nil
}

func ClientBasicAuth(r *http.Request, storage Storage) (clientID string, err error) {
	ctx, span := Tracer.Start(r.Context(), "ClientBasicAuth")
	r = r.WithContext(ctx)
	defer span.End()

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return "", protocol.ErrInvalidClient().WithParent(ErrNoClientCredentials)
	}
	clientID, err = url.QueryUnescape(clientID)
	if err != nil {
		return "", protocol.ErrInvalidClient().WithParent(ErrInvalidAuthHeader)
	}
	clientSecret, err = url.QueryUnescape(clientSecret)
	if err != nil {
		return "", protocol.ErrInvalidClient().WithParent(ErrInvalidAuthHeader)
	}
	if err := storage.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
		return "", protocol.ErrUnauthorizedClient().WithParent(err)
	}
	return clientID, nil
}

type ClientProvider interface {
	Decoder() httphelper.Decoder
	Storage() Storage
}

type clientData struct {
	ClientID string `schema:"client_id"`
	oidc.ClientAssertionParams
}

// ClientIDFromRequest parses the request form and tries to obtain the client ID
// and reports if it is authenticated, using a JWT or static client secrets over
// http basic auth.
//
// If the Provider implements IntrospectorJWTProfile and "client_assertion" is
// present in the form data, JWT assertion will be verified and the
// client ID is taken from there.
// If any of them is absent, basic auth is attempted.
// In absence of basic auth data, the unauthenticated client id from the form
// data is returned.
//
// If no client id can be obtained by any method, oidc.ErrInvalidClient
// is returned with ErrMissingClientID wrapped in it.
func ClientIDFromRequest(r *http.Request, p ClientProvider) (clientID string, authenticated bool, err error) {
	err = r.ParseForm()
	if err != nil {
		return "", false, protocol.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
	}

	ctx, span := Tracer.Start(r.Context(), "ClientIDFromRequest")
	r = r.WithContext(ctx)
	defer span.End()

	data := new(clientData)
	if err = p.Decoder().Decode(data, r.Form); err != nil {
		return "", false, err
	}

	JWTProfile, ok := p.(ClientJWTProfile)
	if ok && data.ClientAssertion != "" {
		// if JWTProfile is supported and client sent an assertion, check it and use it as response
		// regardless if it succeeded or failed
		clientID, err = ClientJWTAuth(r.Context(), data.ClientAssertionParams, JWTProfile)
		return clientID, err == nil, err
	}
	// try basic auth
	clientID, err = ClientBasicAuth(r, p.Storage())
	// if that succeeded, use it
	if err == nil {
		return clientID, true, nil
	}
	// if the client did not send a Basic Auth Header, ignore the `ErrNoClientCredentials`
	// but return other errors immediately
	if !errors.Is(err, ErrNoClientCredentials) {
		return "", false, err
	}

	// if the client did not authenticate (public clients) it must at least send a client_id
	if data.ClientID == "" {
		return "", false, protocol.ErrInvalidClient().WithParent(ErrMissingClientID)
	}
	return data.ClientID, false, nil
}

type ClientCredentials struct {
	ClientID            string `schema:"client_id"`
	ClientSecret        string `schema:"client_secret"`    // Client secret from Basic auth or request body
	ClientAssertion     string `schema:"client_assertion"` // JWT
	ClientAssertionType string `schema:"client_assertion_type"`
}
