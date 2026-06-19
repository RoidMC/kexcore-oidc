// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"fmt"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
)

// =================================================================
// storm.RevocationStore
// =================================================================

func (s *Storage) RevokeToken(_ context.Context, tokenOrTokenID, userID, clientID string) *protocol.Error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// try access tokens
	if token, ok := s.tokens[tokenOrTokenID]; ok {
		if token.ApplicationID != clientID {
			return protocol.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		delete(s.tokens, tokenOrTokenID)
		return nil
	}

	// try refresh tokens
	if token, ok := s.refreshTokens[tokenOrTokenID]; ok {
		if token.ApplicationID != clientID {
			return protocol.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		// also revoke the linked access token
		if token.AccessToken != "" {
			delete(s.tokens, token.AccessToken)
		}
		delete(s.refreshTokens, tokenOrTokenID)
		return nil
	}

	return nil
}

func (s *Storage) GetRefreshTokenInfo(_ context.Context, clientID, token string) (userID, tokenID string, err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	rt, ok := s.refreshTokens[token]
	if !ok {
		return "", "", fmt.Errorf("refresh token not found")
	}
	return rt.UserID, rt.ID, nil
}
