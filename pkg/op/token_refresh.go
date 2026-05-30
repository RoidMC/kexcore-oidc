// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package op

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	httphelper "github.com/roidmc/kexcore-oidc/pkg/http"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type RefreshTokenRequest interface {
	GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetScopes() []string
	GetSubject() string
	SetCurrentScopes(scopes []string)
}

// RefreshTokenRequestSessionID should be implemented if backchannel_logout_session_supported
// is enabled. When supported, the sid Claim must be present in both ID Tokens and
// Logout Tokens.
type RefreshTokenRequestSessionID interface {
	GetSessionID() string
}

// RefreshTokenExchange handles the OAuth 2.0 refresh_token grant, including
// parsing, validating, authorizing the client and finally exchanging the refresh_token for new tokens
func RefreshTokenExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	ctx, span := Tracer.Start(r.Context(), "RefreshTokenExchange")
	defer span.End()
	r = r.WithContext(ctx)

	tokenReq, err := ParseRefreshTokenRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}
	validatedRequest, client, err := ValidateRefreshTokenRequest(r.Context(), tokenReq, exchanger)
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}
	resp, err := CreateTokenResponse(r.Context(), validatedRequest, client, exchanger, true, "", tokenReq.RefreshToken)
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}
	httphelper.MarshalJSON(w, resp)
}

// ParseRefreshTokenRequest parsed the http request into an protocol.RefreshTokenRequest
func ParseRefreshTokenRequest(r *http.Request, decoder httphelper.Decoder) (*protocol.RefreshTokenRequest, error) {
	request := new(protocol.RefreshTokenRequest)
	err := ParseAuthenticatedTokenRequest(r, decoder, request)
	if err != nil {
		return nil, err
	}
	return request, nil
}

// ValidateRefreshTokenRequest validates the refresh_token request parameters including authorization check of the client
// and returns the data representing the original auth request corresponding to the refresh_token
func ValidateRefreshTokenRequest(ctx context.Context, tokenReq *protocol.RefreshTokenRequest, exchanger Exchanger) (RefreshTokenRequest, Client, error) {
	ctx, span := Tracer.Start(ctx, "ValidateRefreshTokenRequest")
	defer span.End()

	if tokenReq.RefreshToken == "" {
		return nil, nil, protocol.ErrInvalidRequest().WithDescription("refresh_token missing")
	}
	request, client, err := AuthorizeRefreshClient(ctx, tokenReq, exchanger)
	if err != nil {
		return nil, nil, err
	}
	if client.GetID() != request.GetClientID() {
		return nil, nil, protocol.ErrInvalidGrant()
	}
	if err = ValidateRefreshTokenScopes(tokenReq.Scopes, request); err != nil {
		return nil, nil, err
	}
	return request, client, nil
}

// ValidateRefreshTokenScopes validates that the requested scope is a subset of the original auth request scope
// it will set the requested scopes as current scopes onto RefreshTokenRequest
// if empty the original scopes will be used
func ValidateRefreshTokenScopes(requestedScopes []string, authRequest RefreshTokenRequest) error {
	if len(requestedScopes) == 0 {
		return nil
	}
	for _, scope := range requestedScopes {
		if !slices.Contains(authRequest.GetScopes(), scope) {
			return protocol.ErrInvalidScope()
		}
	}
	authRequest.SetCurrentScopes(requestedScopes)
	return nil
}

// AuthorizeRefreshClient checks the authorization of the client and that the used method was the one previously registered.
// It than returns the data representing the original auth request corresponding to the refresh_token
func AuthorizeRefreshClient(ctx context.Context, tokenReq *protocol.RefreshTokenRequest, exchanger Exchanger) (request RefreshTokenRequest, client Client, err error) {
	ctx, span := Tracer.Start(ctx, "AuthorizeRefreshClient")
	defer span.End()

	if tokenReq.ClientAssertionType == protocol.ClientAssertionTypeJWTAssertion {
		jwtExchanger, ok := exchanger.(JWTAuthorizationGrantExchanger)
		if !ok || !exchanger.AuthMethodPrivateKeyJWTSupported() {
			return nil, nil, errors.New("auth_method private_key_jwt not supported")
		}
		client, err = AuthorizePrivateJWTKey(ctx, tokenReq.ClientAssertion, jwtExchanger)
		if err != nil {
			return nil, nil, err
		}
		if !ValidateGrantType(client, protocol.GrantTypeRefreshToken) {
			return nil, nil, protocol.ErrUnauthorizedClient()
		}
		request, err = RefreshTokenRequestByRefreshToken(ctx, exchanger.Storage(), tokenReq.RefreshToken)
		return request, client, err
	}
	client, err = exchanger.Storage().GetClientByClientID(ctx, tokenReq.ClientID)
	if err != nil {
		return nil, nil, err
	}
	if !ValidateGrantType(client, protocol.GrantTypeRefreshToken) {
		return nil, nil, protocol.ErrUnauthorizedClient()
	}
	if client.AuthMethod() == protocol.AuthMethodPrivateKeyJWT {
		return nil, nil, protocol.ErrInvalidClient()
	}
	if client.AuthMethod() == protocol.AuthMethodNone {
		request, err = RefreshTokenRequestByRefreshToken(ctx, exchanger.Storage(), tokenReq.RefreshToken)
		return request, client, err
	}
	if client.AuthMethod() == protocol.AuthMethodPost && !exchanger.AuthMethodPostSupported() {
		return nil, nil, protocol.ErrInvalidClient().WithDescription("auth_method post not supported")
	}
	if err = AuthorizeClientIDSecret(ctx, tokenReq.ClientID, tokenReq.ClientSecret, exchanger.Storage()); err != nil {
		return nil, nil, err
	}
	request, err = RefreshTokenRequestByRefreshToken(ctx, exchanger.Storage(), tokenReq.RefreshToken)
	return request, client, err
}

// RefreshTokenRequestByRefreshToken returns the RefreshTokenRequest (data representing the original auth request)
// corresponding to the refresh_token from Storage or an error
func RefreshTokenRequestByRefreshToken(ctx context.Context, storage Storage, refreshToken string) (RefreshTokenRequest, error) {
	ctx, span := Tracer.Start(ctx, "RefreshTokenRequestByRefreshToken")
	defer span.End()

	request, err := storage.TokenRequestByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, protocol.ErrInvalidGrant().WithParent(err)
	}
	return request, nil
}
