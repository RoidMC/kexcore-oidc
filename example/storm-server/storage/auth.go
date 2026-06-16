// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// =================================================================
// storm.AuthStore
// =================================================================

func (s *Storage) CreateAuthRequest(_ context.Context, req *protocol.AuthRequest, userID string) (storm.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	user := s.userStore.GetUserByID(userID)
	ar := authRequestToInternal(req, userID, user)
	ar.ID = uuid.NewString()
	s.authRequests[ar.ID] = ar
	return ar, nil
}

func (s *Storage) AuthRequestByID(_ context.Context, id string) (storm.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	ar, ok := s.authRequests[id]
	if !ok {
		return nil, fmt.Errorf("auth request not found: %s", id)
	}
	return ar, nil
}

// authCodeTTL is the maximum lifetime of an authorization code.
// RFC 6749 §4.1.2: The authorization code MUST expire after a brief
// period of time. FAPI 2.0 Security Profile §5.3.2.1-11 requires 60 seconds.
const authCodeTTL = 60 * time.Second

func (s *Storage) AuthRequestByCode(_ context.Context, code string) (storm.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	authReqID, ok := s.codeToAuthReq[code]
	if !ok {
		// Check if code was already consumed — signal reuse so the
		// caller can revoke previously issued tokens (RFC 6749 §4.1.2).
		if _, used := s.usedCodes[code]; used {
			return nil, fmt.Errorf("authorization code already used")
		}
		return nil, fmt.Errorf("code not found")
	}

	// RFC 6749 §4.1.2: check auth code TTL
	if createdAt, ok := s.codeCreatedAt[code]; ok {
		if time.Since(createdAt) > authCodeTTL {
			// Code expired — clean up
			delete(s.codeToAuthReq, code)
			delete(s.authCodes, authReqID)
			delete(s.codeCreatedAt, code)
			return nil, fmt.Errorf("authorization code expired")
		}
	}

	ar, ok := s.authRequests[authReqID]
	if !ok {
		return nil, fmt.Errorf("auth request not found: %s", authReqID)
	}

	// RFC 6749 §4.1.2: Codes MUST be single-use. Atomically consume
	// the code so a concurrent duplicate request sees "already used".
	delete(s.codeToAuthReq, code)
	s.usedCodes[code] = authReqID
	delete(s.authCodes, authReqID)
	delete(s.codeCreatedAt, code)

	return ar, nil
}

func (s *Storage) SaveAuthCode(_ context.Context, id, code string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, ok := s.authRequests[id]; !ok {
		return fmt.Errorf("auth request not found: %s", id)
	}
	s.authCodes[id] = code
	s.codeToAuthReq[code] = id
	s.codeCreatedAt[code] = time.Now()
	return nil
}

func (s *Storage) DeleteAuthRequest(_ context.Context, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.authRequests, id)
	if code, ok := s.authCodes[id]; ok {
		// Move to usedCodes for code reuse detection
		s.usedCodes[code] = id
		delete(s.codeToAuthReq, code)
		delete(s.authCodes, id)
		delete(s.codeCreatedAt, code)
	}
	return nil
}

// TrackTokenForAuthRequest records that a token was issued for an auth request.
// This is used to revoke tokens when an authorization code is reused.
func (s *Storage) TrackTokenForAuthRequest(authRequestID, tokenID string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.codeTokens[authRequestID] = append(s.codeTokens[authRequestID], tokenID)
}

// RevokeTokensForUsedCode revokes all tokens that were issued for a used code.
// Returns the auth request ID if the code was found, or empty string if not.
func (s *Storage) RevokeTokensForUsedCode(code string) string {
	s.lock.Lock()
	defer s.lock.Unlock()

	authRequestID, ok := s.usedCodes[code]
	if !ok {
		return ""
	}

	// Revoke all tokens issued for this auth request
	if tokenIDs, ok := s.codeTokens[authRequestID]; ok {
		for _, tokenID := range tokenIDs {
			delete(s.tokens, tokenID)
			// Also revoke any refresh tokens linked to this access token
			for rtID, rt := range s.refreshTokens {
				if rt.AccessToken == tokenID {
					delete(s.refreshTokens, rtID)
				}
			}
		}
		delete(s.codeTokens, authRequestID)
	}

	return authRequestID
}

// SetAuthRequestDPoPJKT implements storm.DPoPCodeBindingStore.
func (s *Storage) SetAuthRequestDPoPJKT(_ context.Context, authRequestID string, jkt string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.dpopJKTs[authRequestID] = jkt
	return nil
}

// GetAuthRequestDPoPJKT implements storm.DPoPCodeBindingStore.
func (s *Storage) GetAuthRequestDPoPJKT(_ context.Context, authRequestID string) (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	jkt, ok := s.dpopJKTs[authRequestID]
	if !ok {
		return "", fmt.Errorf("dpop_jkt not found for auth request: %s", authRequestID)
	}
	return jkt, nil
}
