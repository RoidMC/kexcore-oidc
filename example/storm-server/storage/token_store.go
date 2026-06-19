// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	crypto_pkg "github.com/roidmc/kexcore-oidc/v2/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
)

// =================================================================
// storm.TokenStore
// =================================================================

func (s *Storage) CreateAccessToken(ctx context.Context, req storm.TokenRequest, cnf map[string]any) (string, time.Time, error) {
	return s.createAccessToken(ctx, req, cnf)
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req storm.TokenRequest, currentRefreshToken string, cnf map[string]any) (accessTokenID, newRefreshToken string, expiration time.Time, err error) {
	accessTokenID, expiration, err = s.createAccessToken(ctx, req, cnf)
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshToken, err := s.createRefreshToken(ctx, accessTokenID, req, cnf)
	if err != nil {
		return "", "", time.Time{}, err
	}
	newRefreshToken = refreshToken

	// OAuth 2.1 §6.1: invalidate old refresh token (rotation)
	if currentRefreshToken != "" {
		s.lock.Lock()
		delete(s.refreshTokens, currentRefreshToken)
		s.lock.Unlock()
	}

	return accessTokenID, newRefreshToken, expiration, nil
}

func (s *Storage) createAccessToken(_ context.Context, req storm.TokenRequest, cnf map[string]any) (string, time.Time, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	tokenID := uuid.NewString()
	expiration := time.Now().Add(s.tokenTTL)

	token := &Token{
		ID:            tokenID,
		ApplicationID: req.GetClientID(),
		Subject:       req.GetSubject(),
		Audience:      req.GetAudience(),
		Expiration:    expiration,
		Scopes:        req.GetScopes(),
		CNF:           cnf,
	}
	// Preserve claims request from auth request (OIDC Core §5.5)
	if authReq, ok := req.(storm.AuthRequest); ok {
		token.Claims = authReq.GetClaims()
	}
	s.tokens[tokenID] = token

	return tokenID, expiration, nil
}

func (s *Storage) TokenRequestByRefreshToken(_ context.Context, refreshToken string) (storm.RefreshTokenRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.refreshTokens[refreshToken]
	if !ok {
		return nil, fmt.Errorf("refresh token not found")
	}
	return &RefreshTokenRequest{token}, nil
}

// SetTokenCNF stores the cnf (confirmation) claim for a token (RFC 8705 / RFC 9449).
func (s *Storage) SetTokenCNF(_ context.Context, tokenID string, cnf map[string]any) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return fmt.Errorf("token not found: %s", tokenID)
	}
	token.CNF = cnf
	return nil
}

// TokenCNF retrieves the cnf (confirmation) claim for a token (RFC 8705 / RFC 9449).
// Returns nil map if the token has no cnf (not sender-constrained).
func (s *Storage) TokenCNF(_ context.Context, tokenID string) (map[string]any, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return nil, fmt.Errorf("token not found: %s", tokenID)
	}
	return token.CNF, nil
}

// TokenClientID returns the client_id that the token was issued to.
// Implements storm.TokenClientProvider for UserInfo JWT response (OIDC Core §5.3.2).
func (s *Storage) TokenClientID(_ context.Context, tokenID string) (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return "", fmt.Errorf("token not found: %s", tokenID)
	}
	return token.ApplicationID, nil
}

// UserInfoResponseAlg returns the client's registered userinfo_signed_response_alg.
// Implements storm.UserInfoResponseAlgProvider for OIDC Core §5.3.2.
func (s *Storage) UserInfoResponseAlg(_ context.Context, clientID string) (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	c, ok := s.clients[clientID]
	if !ok {
		return "", nil
	}
	return c.userInfoSignedResponseAlg, nil
}

func (s *Storage) createRefreshToken(_ context.Context, accessTokenID string, req storm.TokenRequest, cnf map[string]any) (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	refreshTokenID := uuid.NewString()

	// If the access token is DPoP-bound, copy the jkt to the refresh token
	// so the binding survives access token rotation (RFC 9449 §7.2).
	var dpopJKT string
	if cnf != nil {
		dpopJKT, _ = cnf["jkt"].(string)
	}

	token := &RefreshToken{
		ID:            refreshTokenID,
		Token:         accessTokenID,
		AuthTime:      time.Now(),
		Audience:      req.GetAudience(),
		UserID:        req.GetSubject(),
		ApplicationID: req.GetClientID(),
		Expiration:    time.Now().Add(s.refreshTTL),
		Scopes:        req.GetScopes(),
		AccessToken:   accessTokenID,
		DPoPJKT:       dpopJKT,
	}
	s.refreshTokens[refreshTokenID] = token

	return refreshTokenID, nil
}

// =================================================================
// TokenCrypto provides basic AES token encryption for opaque tokens.
// =================================================================

type TokenCrypto struct {
	key       [32]byte
	method    string // "aes" or "sm4"
	idGenLock sync.Mutex
}

func NewTokenCrypto(key [32]byte, method string) *TokenCrypto {
	return &TokenCrypto{key: key, method: method}
}

func (c *TokenCrypto) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	if c.method == "sm4" {
		return plaintext, nil
	}
	block, err := aes.NewCipher(c.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *TokenCrypto) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	if c.method == "sm4" {
		return ciphertext, nil
	}
	block, err := aes.NewCipher(c.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

func (c *TokenCrypto) EncryptToken(tokenID string) string {
	encrypted, _ := c.Encrypt(context.Background(), []byte(tokenID))
	return base64.RawURLEncoding.EncodeToString(encrypted)
}

// Hash implements storm.UniCrypto.Hash for token hashing (at_hash, c_hash).
func (c *TokenCrypto) Hash(_ context.Context, sigAlgorithm string, data []byte) ([]byte, error) {
	h, err := crypto_pkg.GetHashAlgorithm(sigAlgorithm)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// Sign implements storm.UniCrypto.Sign (not used in this example).
func (c *TokenCrypto) Sign(_ context.Context, keyID string, payload []byte) (string, error) {
	return "", fmt.Errorf("signing not supported by example TokenCrypto")
}

// AlgorithmSuite implements storm.UniCrypto.AlgorithmSuite.
func (c *TokenCrypto) AlgorithmSuite() string {
	if c.method == "sm4" {
		return "SM2+SM3+SM4"
	}
	return "RSA+SHA256+AES"
}
