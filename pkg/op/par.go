// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op

import (
	"context"
	"net/http"
	"time"

	httphelper "github.com/roidmc/kexcore-oidc/pkg/http"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
)

const (
	// DefaultPushedAuthRequestLifetime is the default lifetime of a pushed authorization
	// request URI in seconds. RFC 9126 recommends 600 seconds.
	DefaultPushedAuthRequestLifetime = 600 * time.Second
)

// PushedAuthRequestHandler is the HTTP handler for the Pushed Authorization Request endpoint.
// https://datatracker.ietf.org/doc/html/rfc9126
func PushedAuthRequestHandler(authorizer Authorizer) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := PushedAuthRequest(w, r, authorizer); err != nil {
			RequestError(w, r, err, authorizer.Logger())
		}
	}
}

// PushedAuthRequest handles the pushed authorization request.
// It parses the request, authenticates the client, validates the parameters,
// stores the request, and returns a request_uri.
func PushedAuthRequest(w http.ResponseWriter, r *http.Request, authorizer Authorizer) error {
	ctx, span := Tracer.Start(r.Context(), "PushedAuthRequest")
	r = r.WithContext(ctx)
	defer span.End()

	parStorage, ok := authorizer.Storage().(PushedAuthRequestStorage)
	if !ok {
		return oidc.ErrInvalidRequest().WithDescription("pushed authorization requests not supported")
	}

	authReq, client, err := parseAndValidatePushedAuthRequest(r, authorizer)
	if err != nil {
		return err
	}

	// RFC 9126 Section 2.1: For public clients using the "code" response type,
	// the authorization server MUST require PKCE (code_challenge).
	if client.AuthMethod() == oidc.AuthMethodNone && authReq.ResponseType == oidc.ResponseTypeCode && authReq.CodeChallenge == "" {
		return oidc.ErrInvalidRequest().WithDescription("public clients must use PKCE (code_challenge) for pushed authorization requests with response_type=code")
	}

	requestURI, err := parStorage.StorePushedAuthRequest(ctx, client.GetID(), authReq, DefaultPushedAuthRequestLifetime)
	if err != nil {
		return oidc.ErrServerError().WithDescription("unable to store pushed authorization request").WithParent(err)
	}

	expiresIn := int(DefaultPushedAuthRequestLifetime / time.Second)

	resp := &oidc.PushedAuthResponse{
		RequestURI: requestURI,
		ExpiresIn:  expiresIn,
	}

	w.Header().Set("Cache-Control", "no-store")
	httphelper.MarshalJSON(w, resp)
	return nil
}

// parseAndValidatePushedAuthRequest parses the pushed authorization request from the HTTP request,
// authenticates the client, and validates the authorization request parameters.
func parseAndValidatePushedAuthRequest(r *http.Request, authorizer Authorizer) (*oidc.AuthRequest, Client, error) {
	ctx, span := Tracer.Start(r.Context(), "parseAndValidatePushedAuthRequest")
	r = r.WithContext(ctx)
	defer span.End()

	if err := r.ParseForm(); err != nil {
		return nil, nil, oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
	}

	authReq := new(oidc.AuthRequest)
	if err := authorizer.Decoder().Decode(authReq, r.Form); err != nil {
		return nil, nil, oidc.ErrInvalidRequest().WithDescription("cannot parse pushed authorization request").WithParent(err)
	}

	// Handle request object if present
	if authReq.RequestParam != "" && authorizer.RequestObjectSupported() {
		if err := ParseRequestObject(ctx, authReq, authorizer.Storage(), IssuerFromContext(ctx)); err != nil {
			return nil, nil, err
		}
	}

	if authReq.ClientID == "" {
		return nil, nil, oidc.ErrInvalidRequest().WithDescription("client_id is required")
	}

	client, err := authorizer.Storage().GetClientByClientID(ctx, authReq.ClientID)
	if err != nil {
		return nil, nil, oidc.ErrInvalidClient().WithDescription("unable to retrieve client").WithParent(err)
	}

	// Authenticate the client based on its registered auth method
	if err := authenticatePARClient(r, client, authorizer); err != nil {
		return nil, nil, err
	}

	if authReq.RedirectURI == "" {
		return nil, nil, oidc.ErrInvalidRequest().WithDescription("redirect_uri is required")
	}

	if err := ValidateAuthReqRedirectURI(client, authReq.RedirectURI, authReq.ResponseType); err != nil {
		return nil, nil, err
	}
	authReq.Scopes, err = ValidateAuthReqScopes(client, authReq.Scopes)
	if err != nil {
		return nil, nil, err
	}
	if err := ValidateAuthReqResponseType(client, authReq.ResponseType); err != nil {
		return nil, nil, err
	}
	authReq.MaxAge, err = ValidateAuthReqPrompt(authReq.Prompt, authReq.MaxAge)
	if err != nil {
		return nil, nil, err
	}

	return authReq, client, nil
}

// authenticatePARClient authenticates the client for the PAR endpoint.
// It supports the same methods as the token endpoint.
func authenticatePARClient(r *http.Request, client Client, authorizer Authorizer) error {
	switch client.AuthMethod() {
	case oidc.AuthMethodBasic:
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			return oidc.ErrInvalidClient().WithDescription("client authentication required")
		}
		if clientID != client.GetID() {
			return oidc.ErrInvalidClient().WithDescription("client_id mismatch")
		}
		if err := authorizer.Storage().AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			return oidc.ErrInvalidClient().WithDescription("invalid client credentials").WithParent(err)
		}
	case oidc.AuthMethodPost:
		if err := r.ParseForm(); err != nil {
			return oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
		}
		clientID := r.PostFormValue("client_id")
		clientSecret := r.PostFormValue("client_secret")
		if clientID != client.GetID() {
			return oidc.ErrInvalidClient().WithDescription("client_id mismatch")
		}
		if err := authorizer.Storage().AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			return oidc.ErrInvalidClient().WithDescription("invalid client credentials").WithParent(err)
		}
	case oidc.AuthMethodPrivateKeyJWT:
		if err := r.ParseForm(); err != nil {
			return oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
		}
		assertion := r.PostFormValue("client_assertion")
		if assertion == "" {
			return oidc.ErrInvalidClient().WithDescription("client_assertion required")
		}
		jwtVerifier, ok := authorizer.(ClientJWTProfile)
		if !ok {
			return oidc.ErrInvalidClient().WithDescription("private_key_jwt not supported")
		}
		profile, err := ClientJWTAuth(r.Context(), oidc.ClientAssertionParams{ClientAssertion: assertion}, jwtVerifier)
		if err != nil {
			return err
		}
		if profile != client.GetID() {
			return oidc.ErrInvalidClient().WithDescription("client_assertion issuer mismatch")
		}
	case oidc.AuthMethodNone:
		// Public clients use client_id parameter for identification (RFC 9126 Section 2.1).
		// client_id was already validated in parseAndValidatePushedAuthRequest.
		return nil
	default:
		return oidc.ErrInvalidClient().WithDescription("unsupported client authentication method")
	}
	return nil
}

// PushedAuthRequestStorage is an optional interface that may be implemented by
// implementors of Storage to support Pushed Authorization Requests (PAR).
// https://datatracker.ietf.org/doc/html/rfc9126
type PushedAuthRequestStorage interface {
	// StorePushedAuthRequest stores the pushed authorization request parameters
	// and returns a request_uri that can be used to reference it.
	// The requestURI should be opaque and unique.
	// expiresIn is the lifetime of the request_uri in seconds (RFC 9126 recommends 600).
	StorePushedAuthRequest(ctx context.Context, clientID string, authReq *oidc.AuthRequest, expiresIn time.Duration) (requestURI string, err error)

	// PushedAuthRequestByURI retrieves the stored authorization request by its request_uri.
	// If the request_uri is expired or invalid, it should return an error.
	PushedAuthRequestByURI(ctx context.Context, clientID string, requestURI string) (*oidc.AuthRequest, error)
}
