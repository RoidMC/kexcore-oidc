// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwk"

	crypto_pkg "github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/crypto/gm"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// Storage implements storm.Storage and all capability interfaces.
type Storage struct {
	lock sync.Mutex

	authRequests  map[string]*AuthRequest
	authCodes     map[string]string
	codeToAuthReq map[string]string

	// codeTokens tracks which tokens were issued for each auth request ID.
	// Used to revoke tokens when an authorization code is reused (RFC 6749 §4.1.2).
	codeTokens map[string][]string

	// usedCodes tracks codes that have been used (code -> authRequestID).
	// Used to detect code reuse and revoke associated tokens.
	usedCodes map[string]string

	tokens        map[string]*Token
	refreshTokens map[string]*RefreshToken

	// sessions tracks which users have authenticated (subject → auth_time).
	// A real implementation would use cookies or a distributed session store.
	sessions map[string]time.Time

	userStore UserStore

	signingKeys []signingKey

	tokenTTL   time.Duration
	refreshTTL time.Duration
	issuer     string
}

// registrationTokens maps registration_access_token -> clientID.
var registrationTokens = make(map[string]string)

// registrations stores the full registration data (clientID -> *storm.ClientRegistration).
var registrations = make(map[string]*storm.ClientRegistration)

type signingKey struct {
	id           string
	algorithm    string
	use          string
	certChain    [][]byte // DER-encoded X.509 certificate chain (x5c)
	rsaKey       *rsa.PrivateKey
	ecdsaKey     *ecdsa.PrivateKey
	ed25519Key   ed25519.PrivateKey
	sm2Key       *sm2.PrivateKey
	sm9MasterKey *sm9.SignMasterPublicKey
	sm9UserKey   *sm9.SignPrivateKey
}

func (k *signingKey) ID() string        { return k.id }
func (k *signingKey) Algorithm() string { return k.algorithm }
func (k *signingKey) Use() string       { return k.use }

// CertificateChain implements protocol.CertificateProvider.
func (k *signingKey) CertificateChain() ([][]byte, error) {
	return k.certChain, nil
}

func (k *signingKey) Key() jwk.Key {
	switch {
	case k.rsaKey != nil:
		jk, _ := jwk.Import[jwk.Key](k.rsaKey)
		_ = jk.Set(jwk.AlgorithmKey, k.algorithm)
		_ = jk.Set(jwk.KeyIDKey, k.id)
		return jk
	case k.ecdsaKey != nil:
		jk, _ := jwk.Import[jwk.Key](k.ecdsaKey)
		_ = jk.Set(jwk.AlgorithmKey, k.algorithm)
		_ = jk.Set(jwk.KeyIDKey, k.id)
		return jk
	case k.ed25519Key != nil:
		jk, _ := jwk.Import[jwk.Key](k.ed25519Key)
		_ = jk.Set(jwk.AlgorithmKey, k.algorithm)
		_ = jk.Set(jwk.KeyIDKey, k.id)
		return jk
	case k.sm2Key != nil:
		jk, _ := jwk.Import[jwk.Key](k.sm2Key)
		_ = jk.Set(jwk.AlgorithmKey, k.algorithm)
		_ = jk.Set(jwk.KeyIDKey, k.id)
		return jk
	case k.sm9UserKey != nil:
		return nil
	}
	return nil
}

// GMJWK implements protocol.GMJWKProvider for SM2 and SM9 keys.
func (k *signingKey) GMJWK() protocol.GMJWK {
	if k.sm2Key != nil {
		pubKey := k.sm2Key.PublicKey
		jwk := crypto_pkg.NewSM2JWK(&pubKey, k.id, k.use)
		raw, err := json.Marshal(jwk)
		if err != nil {
			return nil
		}
		return gmJWK(raw)
	}
	if k.sm9UserKey != nil {
		masterPub := k.sm9MasterKey
		jwk, err := crypto_pkg.NewSM9SignJWK(masterPub, k.id, k.use, int(gm.SM9HIDSign))
		if err != nil {
			return nil
		}
		raw, err := json.Marshal(jwk)
		if err != nil {
			return nil
		}
		return gmJWK(raw)
	}
	return nil
}

// gmJWK is a json.RawMessage wrapper implementing protocol.GMJWK.
type gmJWK json.RawMessage

func (j gmJWK) MarshalJSON() ([]byte, error) { return json.RawMessage(j), nil }

var (
	_ storm.Key        = (*signingKey)(nil)
	_ storm.SigningKey = (*signingKey)(nil)
)

func NewStorage(userStore UserStore, algorithms []string) *Storage {
	signingKeys := make([]signingKey, 0, len(algorithms))
	var sharedRSA *rsa.PrivateKey // RS256/RS384/RS512 share one RSA key
	for _, alg := range algorithms {
		switch alg {
		case "RS256", "RS384", "RS512":
			if sharedRSA == nil {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					continue
				}
				sharedRSA = key
			}
			// Generate a self-signed X.509 certificate for demo (x5c/x5t)
			kid := uuid.NewString()
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName:   "KexCore OIDC",
					Organization: []string{"RoidMC Studios"},
				},
				SubjectKeyId:          []byte(kid)[:4],
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(365 * 24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				IsCA:                  true,
			}
			certDER, err := x509.CreateCertificate(rand.Reader, template, template, &sharedRSA.PublicKey, sharedRSA)
			var certChain [][]byte
			if err == nil {
				certChain = [][]byte{certDER}
			}
			signingKeys = append(signingKeys, signingKey{
				id:        kid,
				algorithm: alg,
				use:       "sig",
				rsaKey:    sharedRSA,
				certChain: certChain,
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
		case "SGD_SM3_SM2":
			// Use gmsm SM2 curve via pkg/crypto/gm
			sm2Key, err := gm.SM2GenerateKey()
			if err != nil {
				continue
			}
			signingKeys = append(signingKeys, signingKey{
				id:        uuid.NewString(),
				algorithm: "SGD_SM3_SM2",
				use:       "sig",
				sm2Key:    sm2Key,
			})
		case "SGD_SM3_SM9":
			// SM9 requires a sign master key pair and a user key
			masterKey, err := gm.SM9GenerateSignMasterKey()
			if err != nil {
				continue
			}
			sm9UID := []byte("example-user")
			userKey, err := gm.SM9GenerateSignUserKey(masterKey, sm9UID)
			if err != nil {
				continue
			}
			signingKeys = append(signingKeys, signingKey{
				id:           uuid.NewString(),
				algorithm:    "SGD_SM3_SM9",
				use:          "sig",
				sm9MasterKey: masterKey.Public().(*sm9.SignMasterPublicKey),
				sm9UserKey:   userKey,
			})
		}
	}

	return &Storage{
		authRequests:  make(map[string]*AuthRequest),
		authCodes:     make(map[string]string),
		codeToAuthReq: make(map[string]string),
		codeTokens:    make(map[string][]string),
		usedCodes:     make(map[string]string),
		tokens:        make(map[string]*Token),
		refreshTokens: make(map[string]*RefreshToken),
		sessions:      make(map[string]time.Time),
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

	seen := make(map[string]bool, len(s.signingKeys))
	var algs []string
	for _, k := range s.signingKeys {
		if !seen[k.algorithm] {
			algs = append(algs, k.algorithm)
			seen[k.algorithm] = true
		}
		// RSA keys support both PKCS1-v1_5 (RS*) and PSS (PS*) signing.
		if ps, ok := rsToPS(k.algorithm); ok && !seen[ps] {
			algs = append(algs, ps)
			seen[ps] = true
		}
	}
	slices.Sort(algs)
	return algs, nil
}

// rsToPS maps RS algorithms to their PS equivalents.
// Returns ("", false) if the algorithm is not an RS variant.
func rsToPS(alg string) (string, bool) {
	switch alg {
	case "RS256":
		return "PS256", true
	case "RS384":
		return "PS384", true
	case "RS512":
		return "PS512", true
	default:
		return "", false
	}
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
		// Move to usedCodes for code reuse detection
		s.usedCodes[code] = id
		delete(s.codeToAuthReq, code)
		delete(s.authCodes, id)
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
	// Preserve claims request from auth request (OIDC Core §5.5)
	if authReq, ok := req.(storm.AuthRequest); ok {
		token.Claims = authReq.GetClaims()
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
			userinfo.Nickname = user.Username
			userinfo.Locale = protocol.NewLocale(user.PreferredLanguage)
			userinfo.Zoneinfo = "UTC"
			userinfo.UpdatedAt = protocol.Time(time.Now().Unix())
			// OIDC Core §5.4 requires ALL profile claims to be present
			// with non-empty, valid values.
			userinfo.AppendClaims("middle_name", "N/A")
			userinfo.AppendClaims("profile", "https://example.com")
			userinfo.AppendClaims("picture", "https://example.com/avatar.png")
			userinfo.AppendClaims("website", "https://example.com")
			userinfo.AppendClaims("gender", "other")
			userinfo.AppendClaims("birthdate", "2000-01-01")
		case protocol.ScopeAddress:
			userinfo.Address = &protocol.UserInfoAddress{
				Formatted: "N/A",
			}
		case protocol.ScopePhone:
			userinfo.PhoneNumber = user.Phone
			userinfo.PhoneNumberVerified = protocol.Bool(user.PhoneVerified)
		}
	}

	// OIDC Core §5.5: claims parameter can request specific claims
	// even without the corresponding scope.
	if token.Claims != nil && token.Claims.UserInfo != nil {
		applyUserInfoClaims(userinfo, user, token.Claims.UserInfo)
	}

	return nil
}

// applyUserInfoClaims applies claims requested via the OIDC §5.5 claims parameter
// to the UserInfo response. Claims requested here are returned even if the
// corresponding scope was not requested.
func applyUserInfoClaims(userinfo *protocol.UserInfo, user *User, claims map[string]*protocol.ClaimRequest) {
	for name := range claims {
		switch name {
		case "name":
			userinfo.Name = user.FirstName + " " + user.LastName
		case "given_name":
			userinfo.GivenName = user.FirstName
		case "family_name":
			userinfo.FamilyName = user.LastName
		case "middle_name":
			userinfo.AppendClaims("middle_name", "N/A")
		case "nickname":
			userinfo.Nickname = user.Username
		case "preferred_username":
			userinfo.PreferredUsername = user.Username
		case "profile":
			userinfo.AppendClaims("profile", "https://example.com")
		case "picture":
			userinfo.AppendClaims("picture", "https://example.com/avatar.png")
		case "website":
			userinfo.AppendClaims("website", "https://example.com")
		case "email":
			userinfo.Email = user.Email
			userinfo.EmailVerified = protocol.Bool(user.EmailVerified)
		case "gender":
			userinfo.AppendClaims("gender", "other")
		case "birthdate":
			userinfo.AppendClaims("birthdate", "2000-01-01")
		case "zoneinfo":
			userinfo.Zoneinfo = "UTC"
		case "locale":
			userinfo.Locale = protocol.NewLocale(user.PreferredLanguage)
		case "phone_number":
			userinfo.PhoneNumber = user.Phone
			userinfo.PhoneNumberVerified = protocol.Bool(user.PhoneVerified)
		case "address":
			userinfo.Address = &protocol.UserInfoAddress{
				Formatted: "N/A",
			}
		case "updated_at":
			userinfo.UpdatedAt = protocol.Time(time.Now().Unix())
		}
	}
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

// GetSession implements authorization.SessionProvider.
// It checks whether the given subject has an active session and
// returns the original authentication time.
func (s *Storage) GetSession(_ context.Context, _ *http.Request, _ string) (string, time.Time, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for subj, authTime := range s.sessions {
		if !authTime.IsZero() {
			return subj, authTime, true
		}
	}
	return "", time.Time{}, false
}

// CreateSession records a subject as having an active session.
func (s *Storage) CreateSession(subject string, authTime time.Time) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions[subject] = authTime
}

// =================================================================
// Login support
// =================================================================

func (s *Storage) CheckUsernamePassword(username, password, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	request, ok := s.authRequests[id]
	if !ok {
		return fmt.Errorf("request not found")
	}

	user := s.userStore.GetUserByUsername(username)
	if user != nil && user.Password == password {
		request.UserID = user.ID
		request.done = true
		request.authTime = time.Now()
		if len(request.ACRValues) > 0 {
			request.acr = request.ACRValues[0]
		}
		s.sessions[user.ID] = request.authTime
		return nil
	}
	return fmt.Errorf("invalid username or password")
}

// CompleteAuthRequest implements storm.AutoCompleteAuthRequest.
// It marks an auth request as done with the given subject and
// the original authentication time, without going through the
// login UI. Used for prompt=none with active sessions.
func (s *Storage) CompleteAuthRequest(_ context.Context, id string, subject string, authTime time.Time) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	request, ok := s.authRequests[id]
	if !ok {
		return fmt.Errorf("auth request not found: %s", id)
	}
	if request.done {
		return fmt.Errorf("auth request already completed: %s", id)
	}
	request.UserID = subject
	request.done = true
	request.authTime = authTime
	if len(request.ACRValues) > 0 {
		request.acr = request.ACRValues[0]
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
	// Delegate to crypto_pkg for hash computation
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
// TokenExchangeStore (optional, for RFC 8693 token exchange)
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
	_ storm.DCRStore               = (*Storage)(nil)
)

// =================================================================
// DCRStore (Dynamic Client Registration)
// =================================================================

type clientRegistration struct {
	*storm.ClientRegistration
	clients map[string]*Client // registered clients keyed by clientID
}

func (s *Storage) CreateClient(_ context.Context, req *storm.RegistrationRequest, clientID, clientSecret, accessToken, uri string) (*storm.ClientRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Store the registered client
	client := &Client{
		id:            clientID,
		secret:        clientSecret,
		redirectURIs:  req.RedirectURIs,
		authMethod:    protocol.AuthMethodBasic,
		loginURLFn:    defaultLoginURL,
		responseTypes: []protocol.ResponseType{protocol.ResponseTypeCode},
		grantTypes:    []protocol.GrantType{protocol.GrantTypeCode, protocol.GrantTypeRefreshToken},
	}
	clients[clientID] = client

	reg := &storm.ClientRegistration{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		RegistrationAccessToken: accessToken,
		RegistrationClientURI:   uri,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0,
		ApplicationType:         req.ApplicationType,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		ResponseTypes:           req.ResponseTypes,
		GrantTypes:              req.GrantTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scope:                   req.Scope,
		JWKSURI:                 req.JWKSURI,
		JWKS:                    req.JWKS,
	}

	// Store registration data for later lookup
	registrationTokens[accessToken] = clientID
	registrations[clientID] = reg

	return reg, nil
}

func (s *Storage) GetClientRegistration(_ context.Context, clientID string) (*storm.ClientRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	reg, ok := registrations[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	return reg, nil
}

func (s *Storage) GetClientRegistrationByToken(_ context.Context, token string) (*storm.ClientRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	clientID, ok := registrationTokens[token]
	if !ok {
		return nil, fmt.Errorf("no client found for token")
	}

	reg, ok := registrations[clientID]
	if !ok {
		return nil, fmt.Errorf("no client found for token")
	}

	return reg, nil
}

func (s *Storage) UpdateClientRegistration(_ context.Context, clientID string, update *storm.RegistrationRequest) (*storm.ClientRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	client, ok := clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	reg, ok := registrations[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	if len(update.RedirectURIs) > 0 {
		client.redirectURIs = update.RedirectURIs
		reg.RedirectURIs = update.RedirectURIs
	}

	return reg, nil
}

func (s *Storage) DeleteClientRegistration(_ context.Context, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Remove the registration token
	reg, ok := registrations[clientID]
	if ok && reg.RegistrationAccessToken != "" {
		delete(registrationTokens, reg.RegistrationAccessToken)
	}

	delete(registrations, clientID)
	delete(clients, clientID)
	return nil
}
