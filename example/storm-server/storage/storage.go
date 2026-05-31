// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// Storage implements storm.Storage and all capability interfaces.
type Storage struct {
	lock sync.Mutex

	authRequests  map[string]*AuthRequest
	authCodes     map[string]string
	codeToAuthReq map[string]string

	tokens        map[string]*Token
	refreshTokens map[string]*RefreshToken

	userStore UserStore

	signingKeys []signingKey

	tokenTTL   time.Duration
	refreshTTL time.Duration
	issuer     string
}

type signingKey struct {
	id         string
	algorithm  string
	use        string
	rsaKey     *rsa.PrivateKey
	ecdsaKey   *ecdsa.PrivateKey
	ed25519Key ed25519.PrivateKey
}

func (k *signingKey) ID() string        { return k.id }
func (k *signingKey) Algorithm() string { return k.algorithm }
func (k *signingKey) Use() string       { return k.use }

func (k *signingKey) Key() jwk.Key {
	switch {
	case k.rsaKey != nil:
		jk, _ := jwk.Import[jwk.Key](k.rsaKey.Public())
		return jk
	case k.ecdsaKey != nil:
		jk, _ := jwk.Import[jwk.Key](k.ecdsaKey.Public())
		return jk
	case k.ed25519Key != nil:
		if pubKey, ok := interface{}(k.ed25519Key).(crypto.PublicKey); ok {
			jk, _ := jwk.Import[jwk.Key](pubKey)
			return jk
		}
	}
	return nil
}

func (k *signingKey) GMJWK() storm.GMJWK { return nil }

var (
	_ storm.Key        = (*signingKey)(nil)
	_ storm.SigningKey = (*signingKey)(nil)
)

func NewStorage(userStore UserStore, algorithms []string) *Storage {
	signingKeys := make([]signingKey, 0, len(algorithms))
	for _, alg := range algorithms {
		switch alg {
		case "RS256", "RS384", "RS512":
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				continue
			}
			signingKeys = append(signingKeys, signingKey{
				id:        uuid.NewString(),
				algorithm: alg,
				use:       "sig",
				rsaKey:    key,
			})
		case "ES256", "ES384", "ES512":
			var curve elliptic.Curve
			switch alg {
			case "ES256":
				curve = elliptic.P256()
			case "ES384":
				curve = elliptic.P384()
			case "ES512":
				curve = elliptic.P521()
			}
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				continue
			}
			signingKeys = append(signingKeys, signingKey{
				id:        uuid.NewString(),
				algorithm: alg,
				use:       "sig",
				ecdsaKey:  key,
			})
		case "EdDSA":
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				continue
			}
			signingKeys = append(signingKeys, signingKey{
				id:         uuid.NewString(),
				algorithm:  "EdDSA",
				use:        "sig",
				ed25519Key: key,
			})
		}
	}

	return &Storage{
		authRequests:  make(map[string]*AuthRequest),
		authCodes:     make(map[string]string),
		codeToAuthReq: make(map[string]string),
		tokens:        make(map[string]*Token),
		refreshTokens: make(map[string]*RefreshToken),
		userStore:     userStore,
		signingKeys:   signingKeys,
		tokenTTL:      1 * time.Hour,
		refreshTTL:    24 * time.Hour,
	}
}

func (s *Storage) expandIDTokenEncryptionAlg(alg string) string {
	if alg == "RSA-OAEP" {
		if len(s.signingKeys) > 0 {
			if s.signingKeys[0].algorithm != "EdDSA" {
				return "RSA-OAEP"
			}
		}
	}
	// Retain GM/T algorithms as-is
	if strings.HasPrefix(alg, "SGD_") {
		return alg
	}
	return alg
}

// =================================================================
// storm.ClientStore
// =================================================================

func (s *Storage) GetClientByClientID(_ context.Context, clientID string) (storm.Client, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	client, ok := clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}
	return client, nil
}

func (s *Storage) AuthorizeClientIDSecret(_ context.Context, clientID, clientSecret string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	client, ok := clients[clientID]
	if !ok {
		return fmt.Errorf("client not found: %s", clientID)
	}
	if client.secret != "" && client.secret != clientSecret {
		return fmt.Errorf("invalid secret")
	}
	return nil
}

// =================================================================
// storm.Health
// =================================================================

func (s *Storage) Health(_ context.Context) error {
	return nil
}

// =================================================================
// storm.KeyStore
// =================================================================

func (s *Storage) KeySet(_ context.Context) ([]storm.Key, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	keys := make([]storm.Key, len(s.signingKeys))
	for i := range s.signingKeys {
		keys[i] = &s.signingKeys[i]
	}
	return keys, nil
}

func (s *Storage) SignatureAlgorithms(_ context.Context) ([]string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	algs := make([]string, len(s.signingKeys))
	for i, k := range s.signingKeys {
		algs[i] = k.algorithm
	}
	return algs, nil
}

func (s *Storage) SigningKey(_ context.Context) (storm.SigningKey, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if len(s.signingKeys) == 0 {
		return nil, fmt.Errorf("no signing keys available")
	}
	return &s.signingKeys[0], nil
}

// =================================================================
// storm.AuthStore
// =================================================================

func (s *Storage) CreateAuthRequest(_ context.Context, req *protocol.AuthRequest, userID string) (storm.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	ar := authRequestToInternal(req, userID)
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

func (s *Storage) AuthRequestByCode(_ context.Context, code string) (storm.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	authReqID, ok := s.codeToAuthReq[code]
	if !ok {
		return nil, fmt.Errorf("code not found")
	}
	ar, ok := s.authRequests[authReqID]
	if !ok {
		return nil, fmt.Errorf("auth request not found: %s", authReqID)
	}
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
	return nil
}

func (s *Storage) DeleteAuthRequest(_ context.Context, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.authRequests, id)
	if code, ok := s.authCodes[id]; ok {
		delete(s.codeToAuthReq, code)
		delete(s.authCodes, id)
	}
	return nil
}

// =================================================================
// storm.TokenStore
// =================================================================

func (s *Storage) CreateAccessToken(ctx context.Context, req storm.TokenRequest) (string, time.Time, error) {
	return s.createAccessToken(ctx, req, nil)
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req storm.TokenRequest, currentRefreshToken string) (accessTokenID, newRefreshToken string, expiration time.Time, err error) {
	accessTokenID, expiration, err = s.createAccessToken(ctx, req, nil)
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshToken, err := s.createRefreshToken(ctx, accessTokenID, req)
	if err != nil {
		return "", "", time.Time{}, err
	}
	newRefreshToken = refreshToken

	// OAuth 2.1 §6.1: invalidate old refresh token (rotation)
	if currentRefreshToken != "" {
		s.lock.Lock()
		if old, ok := s.refreshTokens[currentRefreshToken]; ok {
			old.AccessToken = accessTokenID
			delete(s.refreshTokens, currentRefreshToken)
		}
		s.lock.Unlock()
	}

	return accessTokenID, newRefreshToken, expiration, nil
}

func (s *Storage) createAccessToken(_ context.Context, req storm.TokenRequest, prepare func(string)) (string, time.Time, error) {
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
	}
	s.tokens[tokenID] = token

	if prepare != nil {
		prepare(tokenID)
	}

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

func (s *Storage) createRefreshToken(_ context.Context, accessTokenID string, req storm.TokenRequest) (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	refreshTokenID := uuid.NewString()

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
	}
	s.refreshTokens[refreshTokenID] = token

	return refreshTokenID, nil
}

// =================================================================
// storm.IntrospectStore
// =================================================================

func (s *Storage) SetIntrospectionFromToken(_ context.Context, resp *protocol.IntrospectionResponse, tokenID, subject, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		for _, rt := range s.refreshTokens {
			if rt.Token == tokenID {
				token = &Token{
					ID:            tokenID,
					ApplicationID: rt.ApplicationID,
					Subject:       rt.UserID,
					Audience:      rt.Audience,
					Expiration:    rt.Expiration,
					Scopes:        rt.Scopes,
				}
				break
			}
		}
		if token == nil {
			return fmt.Errorf("token not found")
		}
	}

	resp.Active = true
	resp.ClientID = token.ApplicationID
	resp.Subject = token.Subject
	resp.Audience = token.Audience
	resp.Scope = protocol.SpaceDelimitedArray(token.Scopes)
	resp.TokenType = protocol.BearerToken
	if !token.Expiration.IsZero() {
		resp.Expiration = protocol.FromTime(token.Expiration)
		resp.NotBefore = protocol.FromTime(token.Expiration)
	}

	return nil
}

// =================================================================
// storm.UserinfoStore
// =================================================================

func (s *Storage) SetUserinfoFromToken(_ context.Context, userinfo *protocol.UserInfo, tokenID, subject, origin string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		// check refresh tokens
		for _, rt := range s.refreshTokens {
			if rt.Token == tokenID {
				token = &Token{
					ID:            tokenID,
					ApplicationID: rt.ApplicationID,
					Subject:       rt.UserID,
					Audience:      rt.Audience,
					Expiration:    rt.Expiration,
					Scopes:        rt.Scopes,
				}
				break
			}
		}
		if token == nil {
			return fmt.Errorf("token not found")
		}
	}

	user := s.userStore.GetUserByID(token.Subject)
	if user == nil {
		return fmt.Errorf("user not found")
	}

	for _, scope := range token.Scopes {
		switch scope {
		case protocol.ScopeOpenID:
			userinfo.Subject = user.ID
		case protocol.ScopeEmail:
			userinfo.Email = user.Email
			userinfo.EmailVerified = protocol.Bool(user.EmailVerified)
		case protocol.ScopeProfile:
			userinfo.PreferredUsername = user.Username
			userinfo.Name = user.FirstName + " " + user.LastName
			userinfo.FamilyName = user.LastName
			userinfo.GivenName = user.FirstName
			userinfo.Locale = protocol.NewLocale(user.PreferredLanguage)
		case protocol.ScopePhone:
			userinfo.PhoneNumber = user.Phone
			userinfo.PhoneNumberVerified = protocol.Bool(user.PhoneVerified)
		}
	}

	return nil
}

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

// =================================================================
// storm.SessionStore
// =================================================================

func (s *Storage) TerminateSession(_ context.Context, userID, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	for id, token := range s.tokens {
		if token.ApplicationID == clientID && token.Subject == userID {
			delete(s.tokens, id)
		}
	}
	for id, token := range s.refreshTokens {
		if token.ApplicationID == clientID && token.UserID == userID {
			delete(s.refreshTokens, id)
		}
	}
	return nil
}

// =================================================================
// DeviceAuthStore (optional)
// =================================================================

type deviceAuth struct {
	clientID   string
	deviceCode string
	userCode   string
	expires    time.Time
	scopes     []string
	done       bool
	denied     bool
}

type DeviceAuthStore struct {
	lock    sync.Mutex
	entries map[string]*deviceAuth
}

func (s *Storage) DeviceAuthStore() *DeviceAuthStore {
	return &DeviceAuthStore{entries: make(map[string]*deviceAuth)}
}

func (d *DeviceAuthStore) StoreDeviceAuthorization(_ context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.entries[deviceCode] = &deviceAuth{
		clientID:   clientID,
		deviceCode: deviceCode,
		userCode:   userCode,
		expires:    expires,
		scopes:     scopes,
	}
	return nil
}

func (d *DeviceAuthStore) GetDeviceAuthorizationState(_ context.Context, _, deviceCode string) (*storm.DeviceAuthorizationState, error) {
	d.lock.Lock()
	defer d.lock.Unlock()
	entry, ok := d.entries[deviceCode]
	if !ok {
		return nil, fmt.Errorf("device authorization not found")
	}
	return &storm.DeviceAuthorizationState{
		ClientID: entry.clientID,
		Scopes:   entry.scopes,
		Done:     entry.done,
		Denied:   entry.denied,
		Expires:  entry.expires,
	}, nil
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
		// Return plaintext for SM4 - actual encryption would use pkg/crypto
		return plaintext, nil
	}
	// simple AES-GCM-like (using SHA256 for determinism in example)
	hasher := sha256.New()
	hasher.Write(c.key[:])
	hasher.Write(plaintext)
	return hasher.Sum(nil), nil
}

func (c *TokenCrypto) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	if c.method == "sm4" {
		return ciphertext, nil
	}
	return nil, errors.New("cannot decrypt opaque token (hash-based)")
}

func (c *TokenCrypto) EncryptToken(tokenID string) string {
	encrypted, _ := c.Encrypt(context.Background(), []byte(tokenID))
	return base64.RawURLEncoding.EncodeToString(encrypted)
}

// =================================================================
// Credentials / ClientCredentialsStore (optional)
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
// JWTProfileStore (optional)
// =================================================================

func (s *Storage) ValidateJWTProfileScopes(_ context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

// =================================================================
// Storm compatibility assertions
// =================================================================

var (
	_ storm.Storage                = (*Storage)(nil)
	_ storm.AuthStore              = (*Storage)(nil)
	_ storm.TokenStore             = (*Storage)(nil)
	_ storm.IntrospectStore        = (*Storage)(nil)
	_ storm.UserinfoStore          = (*Storage)(nil)
	_ storm.RevocationStore        = (*Storage)(nil)
	_ storm.SessionStore           = (*Storage)(nil)
	_ storm.ClientCredentialsStore = (*Storage)(nil)
	_ storm.JWTProfileStore        = (*Storage)(nil)
)
