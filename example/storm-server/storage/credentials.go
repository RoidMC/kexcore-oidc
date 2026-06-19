// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
)

// =================================================================
// storm.ClientCredentialsStore (optional)
// =================================================================

func (s *Storage) ClientCredentials(_ context.Context, clientID, clientSecret string) (storm.Client, error) {
	client, err := s.GetClientByClientID(nil, clientID)
	if err != nil {
		return nil, err
	}
	_ = clientSecret
	return client, nil
}

func (s *Storage) ClientCredentialsTokenRequest(_ context.Context, clientID string, scopes []string) (storm.TokenRequest, error) {
	return &clientCredentialsTokenRequest{
		clientID: clientID,
		subject:  clientID,
		scopes:   scopes,
	}, nil
}

type clientCredentialsTokenRequest struct {
	clientID string
	subject  string
	scopes   []string
}

func (r *clientCredentialsTokenRequest) GetSubject() string    { return r.subject }
func (r *clientCredentialsTokenRequest) GetAudience() []string { return []string{r.clientID} }
func (r *clientCredentialsTokenRequest) GetClientID() string   { return r.clientID }
func (r *clientCredentialsTokenRequest) GetScopes() []string   { return r.scopes }

// =================================================================
// storm.JWTProfileStore (optional)
// =================================================================

func (s *Storage) ValidateJWTProfileScopes(_ context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

// =================================================================
// storm.TokenExchangeStore (optional, for RFC 8693 token exchange)
// =================================================================

func (s *Storage) ValidateTokenExchangeRequest(_ context.Context, req storm.TokenExchangeRequest) error {
	if req.GetRequestedTokenType() == "" {
		req.SetRequestedTokenType(protocol.RefreshTokenType)
	}
	return nil
}

func (s *Storage) CreateTokenExchangeRequest(_ context.Context, _ storm.TokenExchangeRequest) error {
	return nil
}

func (s *Storage) GetPrivateClaimsFromTokenExchangeRequest(_ context.Context, _ storm.TokenExchangeRequest) (map[string]any, error) {
	return nil, nil
}

func (s *Storage) SetUserinfoFromTokenExchangeRequest(_ context.Context, _ *protocol.UserInfo, _ storm.TokenExchangeRequest) error {
	return nil
}
