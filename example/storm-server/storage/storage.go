// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
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

	clients       map[string]*Client // registered clients (clientID -> *Client)
	authRequests  map[string]*AuthRequest
	authCodes     map[string]string
	codeToAuthReq map[string]string

	// codeTokens tracks which tokens were issued for each auth request ID.
	// Used to revoke tokens when an authorization code is reused (RFC 6749 §4.1.2).
	codeTokens map[string][]string

	// usedCodes tracks codes that have been used (code -> authRequestID).
	// Used to detect code reuse and revoke associated tokens.
	usedCodes map[string]string

	// codeCreatedAt tracks when each authorization code was created.
	// Used to enforce auth code TTL (RFC 6749 §4.1.2: codes MUST expire
	// after a maximum of 60 seconds).
	codeCreatedAt map[string]time.Time

	tokens        map[string]*Token
	refreshTokens map[string]*RefreshToken

	// sessions tracks active sessions by session ID.
	// Key: session ID, Value: session info including subject and auth time.
	sessions map[string]*sessionInfo

	// clientSessions tracks which clients have active sessions for a subject.
	// Used by BackChannelStore.ClientsForSession to find RPs to notify on logout.
	clientSessions map[string]map[string]*clientSession

	// registrationTokens maps registration_access_token -> clientID.
	registrationTokens map[string]string

	// registrations stores the full registration data (clientID -> *storm.ClientRegistration).
	registrations map[string]*storm.ClientRegistration

	// deviceAuthStore handles device authorization grant (RFC 8628).
	*DeviceAuthStore

	// parStore handles pushed authorization requests (RFC 9126).
	*PARStore

	userStore UserStore

	signingKeys []signingKey

	tokenTTL   time.Duration
	refreshTTL time.Duration
	issuer     string
}

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
		_ = jk.Set(jwk.KeyUsageKey, k.use)
		return jk
	case k.ecdsaKey != nil:
		jk, _ := jwk.Import[jwk.Key](k.ecdsaKey)
		_ = jk.Set(jwk.AlgorithmKey, k.algorithm)
		_ = jk.Set(jwk.KeyIDKey, k.id)
		_ = jk.Set(jwk.KeyUsageKey, k.use)
		return jk
	case k.ed25519Key != nil:
		jk, _ := jwk.Import[jwk.Key](k.ed25519Key)
		_ = jk.Set(jwk.AlgorithmKey, k.algorithm)
		_ = jk.Set(jwk.KeyIDKey, k.id)
		_ = jk.Set(jwk.KeyUsageKey, k.use)
		return jk
	case k.sm2Key != nil:
		jk, _ := jwk.Import[jwk.Key](k.sm2Key)
		_ = jk.Set(jwk.AlgorithmKey, k.algorithm)
		_ = jk.Set(jwk.KeyIDKey, k.id)
		_ = jk.Set(jwk.KeyUsageKey, k.use)
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
		clients:            make(map[string]*Client),
		authRequests:       make(map[string]*AuthRequest),
		authCodes:          make(map[string]string),
		codeToAuthReq:      make(map[string]string),
		codeTokens:         make(map[string][]string),
		usedCodes:          make(map[string]string),
		codeCreatedAt:      make(map[string]time.Time),
		tokens:             make(map[string]*Token),
		refreshTokens:      make(map[string]*RefreshToken),
		sessions:           make(map[string]*sessionInfo),
		clientSessions:     make(map[string]map[string]*clientSession),
		registrationTokens: make(map[string]string),
		registrations:      make(map[string]*storm.ClientRegistration),
		DeviceAuthStore:    &DeviceAuthStore{entries: make(map[string]*deviceAuth), byCode: make(map[string]*deviceAuth)},
		PARStore:           NewPARStore(),
		userStore:          userStore,
		signingKeys:        signingKeys,
		tokenTTL:           1 * time.Hour,
		refreshTTL:         24 * time.Hour,
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

	client, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}
	return client, nil
}

func (s *Storage) AuthorizeClientIDSecret(_ context.Context, clientID, clientSecret string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	client, ok := s.clients[clientID]
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
		if ps, ok := rsToPS(k.algorithm); ok && !seen[ps] {
			algs = append(algs, ps)
			seen[ps] = true
		}
	}
	slices.Sort(algs)
	return algs, nil
}

// rsToPS maps RS algorithms to their PS equivalents.
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
// Storm compatibility assertions
// =================================================================

// RotateSigningKey generates a new RSA-2048/RS256 signing key and prepends it
// to the key set. Old keys remain in KeySet() for token verification.
// Note: this is an example server that restarts between test sessions, so
// unbounded key accumulation is not a concern in practice.
func (s *Storage) RotateSigningKey() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	sk := signingKey{
		id:        uuid.NewString(),
		algorithm: "RS256",
		use:       "sig",
		rsaKey:    key,
	}
	s.signingKeys = append([]signingKey{sk}, s.signingKeys...)
	return nil
}

// SigningKeyCount returns the number of signing keys.
func (s *Storage) SigningKeyCount() int {
	s.lock.Lock()
	defer s.lock.Unlock()
	return len(s.signingKeys)
}

var (
	_ storm.Storage                = (*Storage)(nil)
	_ storm.AuthStore              = (*Storage)(nil)
	_ storm.TokenStore             = (*Storage)(nil)
	_ storm.IntrospectStore        = (*Storage)(nil)
	_ storm.UserinfoStore          = (*Storage)(nil)
	_ storm.RevocationStore        = (*Storage)(nil)
	_ storm.SessionStore           = (*Storage)(nil)
	_ storm.BackChannelStore       = (*Storage)(nil)
	_ storm.DeviceAuthStore        = (*Storage)(nil)
	_ storm.PARStore               = (*Storage)(nil)
	_ storm.ClientCredentialsStore = (*Storage)(nil)
	_ storm.JWTProfileStore        = (*Storage)(nil)
	_ storm.DCRStore               = (*Storage)(nil)
)
