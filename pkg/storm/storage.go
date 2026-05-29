package storm

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"golang.org/x/text/language"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Storage is the minimal storage contract required by StormEngine.
// Users implement this interface and pass it to Engine.
//
// Engine automatically detects which optional capability interfaces
// the storage implements, and each plugin consumes only the interfaces
// it needs. This eliminates the giant monolithic Storage interface.
type Storage interface {
	// ClientStore provides client lookup and credential verification.
	ClientStore

	// KeyStore provides JWKS and signing key access.
	KeyStore

	// Health is used by the /ready probe.
	Health(ctx context.Context) error
}

// ClientStore is the minimal client management interface.
type ClientStore interface {
	GetClientByClientID(ctx context.Context, clientID string) (Client, error)
	AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error
}

// Client is the minimal client interface.
type Client interface {
	GetID() string
	AuthMethod() protocol.AuthMethod
	LoginURL(id string) string
}

// KeyStore provides cryptographic key access.
type KeyStore interface {
	KeySet(ctx context.Context) ([]Key, error)
	SignatureAlgorithms(ctx context.Context) ([]string, error)
	SigningKey(ctx context.Context) (SigningKey, error)
}

// Key represents a JWK for JWKS publication.
// Standard keys (RSA, ECDSA, EdDSA) return a non-nil JWK().
// GM/T keys (SM2, SM9) return a non-nil GMJWK().
// At least one of JWK() or GMJWK() must return a non-nil value.
type Key interface {
	ID() string
	Algorithm() string
	Use() string
	Key() jwk.Key

	// GMJWK returns the GM/T JWK representation for national cryptography keys.
	// Returns nil for standard (non-GM/T) keys.
	// When non-nil, the JWKS endpoint uses this instead of Key().
	GMJWK() GMJWK
}

// GMJWK represents a GM/T (国密) JSON Web Key for JWKS publication.
// This is needed because the jwx library does not recognize SM2/SM9 curves,
// so standard jwk.Key cannot represent these keys.
type GMJWK interface {
	// MarshalJSON serializes the GM/T JWK to JSON.
	// The output must be a valid JSON object per GM/T 0125.4-2022.
	MarshalJSON() ([]byte, error)
}

// SigningKey represents a key used for token signing.
type SigningKey interface {
	ID() string
	Algorithm() string
	Key() jwk.Key
}

// GMSigningKey extends SigningKey for GM/T signing keys (SM2, SM9).
// Plugins that need to sign with GM/T algorithms should check for this interface.
type GMSigningKey interface {
	SigningKey

	// GMSigner returns the crypto.Signer for GM/T signing operations.
	// The returned Signer can produce JWS signatures using SGD_SM3_SM2 or SGD_SM3_SM9.
	GMSigner() *GMTokenSigner
}

// GMTokenSigner provides GM/T token signing capability.
// It wraps pkg/crypto.Signer for use in storm plugins.
type GMTokenSigner struct {
	// Algorithm is the signing algorithm (e.g. "SGD_SM3_SM2", "SGD_SM3_SM9").
	Algorithm string
	// KeyID is the JWK key ID.
	KeyID string
	// SignFunc signs the payload and returns compact JWS serialization.
	SignFunc func(payload []byte) (string, error)
}

// Sign signs the payload and returns the compact JWS serialization.
func (s *GMTokenSigner) Sign(payload []byte) (string, error) {
	return s.SignFunc(payload)
}

// AuthStore is required by the Authorization plugin.
type AuthStore interface {
	CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (AuthRequest, error)
	AuthRequestByID(ctx context.Context, id string) (AuthRequest, error)
	AuthRequestByCode(ctx context.Context, code string) (AuthRequest, error)
	SaveAuthCode(ctx context.Context, id, code string) error
	DeleteAuthRequest(ctx context.Context, id string) error
}

// AuthRequest represents an in-flight authorization request.
type AuthRequest interface {
	GetID() string
	GetACR() string
	GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetCodeChallenge() *oidc.CodeChallenge
	GetNonce() string
	GetRedirectURI() string
	GetResponseType() oidc.ResponseType
	GetResponseMode() oidc.ResponseMode
	GetScopes() []string
	GetState() string
	GetSubject() string
	Done() bool
}

// TokenStore is required by the Token plugin for access/refresh token operations.
type TokenStore interface {
	CreateAccessToken(ctx context.Context, req TokenRequest) (tokenID string, expiration time.Time, err error)
	CreateAccessAndRefreshTokens(ctx context.Context, req TokenRequest, currentRefreshToken string) (accessTokenID, newRefreshToken string, expiration time.Time, err error)
	TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (RefreshTokenRequest, error)
}

// TokenRequest is the common interface for all token creation requests.
type TokenRequest interface {
	GetSubject() string
	GetAudience() []string
	GetClientID() string
	GetScopes() []string
}

// RefreshTokenRequest extends TokenRequest for refresh token operations.
type RefreshTokenRequest interface {
	TokenRequest
	GetAMR() []string
	GetAuthTime() time.Time
	GetCodeChallenge() *oidc.CodeChallenge
	GetNonce() string
	GetID() string
	SetCurrentScopes(scopes []string)
}

// IntrospectStore is required by the Introspection plugin.
type IntrospectStore interface {
	SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, tokenID, subject, clientID string) error
}

// UserinfoStore is required by the UserInfo plugin.
type UserinfoStore interface {
	SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error
}

// RevocationStore is required by the Revocation plugin.
type RevocationStore interface {
	RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *protocol.Error
	GetRefreshTokenInfo(ctx context.Context, clientID, token string) (userID, tokenID string, err error)
}

// SessionStore is required by the EndSession plugin.
type SessionStore interface {
	TerminateSession(ctx context.Context, userID, clientID string) error
}

// DeviceAuthStore is required by the Device Authorization plugin.
type DeviceAuthStore interface {
	StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error
	GetDeviceAuthorizationState(ctx context.Context, clientID, deviceCode string) (*DeviceAuthorizationState, error)
}

// DeviceAuthorizationState represents the current state of a device auth flow.
type DeviceAuthorizationState struct {
	ClientID string
	Scopes   []string
	Done     bool
	Denied   bool
	Expires  time.Time
}

// ClientCredentialsStore is required by the Client Credentials grant.
type ClientCredentialsStore interface {
	ClientCredentials(ctx context.Context, clientID, clientSecret string) (Client, error)
	ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (TokenRequest, error)
}

// JWTProfileStore is required by the JWT Profile grant.
type JWTProfileStore interface {
	ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error)
}

// TokenExchangeStore is required by the Token Exchange plugin.
type TokenExchangeStore interface {
	ValidateTokenExchangeRequest(ctx context.Context, req TokenExchangeRequest) error
	CreateTokenExchangeRequest(ctx context.Context, req TokenExchangeRequest) error
	GetPrivateClaimsFromTokenExchangeRequest(ctx context.Context, req TokenExchangeRequest) (map[string]any, error)
	SetUserinfoFromTokenExchangeRequest(ctx context.Context, userinfo *oidc.UserInfo, req TokenExchangeRequest) error
}

// TokenExchangeRequest represents a validated token exchange request.
type TokenExchangeRequest interface {
	TokenRequest
	GetRequestedTokenType() oidc.TokenType
	GetSubjectTokenType() oidc.TokenType
	GetActorTokenType() oidc.TokenType
	SetCurrentScopes(scopes []string)
	SetRequestedTokenType(tokenType oidc.TokenType)
}

// DCRStore is required by the Dynamic Client Registration plugin.
type DCRStore interface {
	CreateClient(ctx context.Context, client *RegistrationRequest, clientID, clientSecret, accessToken, uri string) (*ClientRegistration, error)
	GetClientRegistration(ctx context.Context, clientID string) (*ClientRegistration, error)
	GetClientRegistrationByToken(ctx context.Context, token string) (*ClientRegistration, error)
	UpdateClientRegistration(ctx context.Context, clientID string, update *RegistrationRequest) (*ClientRegistration, error)
	DeleteClientRegistration(ctx context.Context, clientID string) error
}

// RegistrationRequest represents a dynamic client registration request.
type RegistrationRequest struct {
	ApplicationType         string
	ClientName              string
	ClientURI               string
	LogoURI                 string
	RedirectURIs            []string
	ResponseTypes           []string
	GrantTypes              []string
	TokenEndpointAuthMethod string
	Scope                   string
	Contacts                []string
	JWKSURI                 string
	JWKS                    []byte
	PolicyURI               string
	TOSURI                  string
	SoftwareID              string
	SoftwareVersion         string
}

// ClientRegistration represents a registered client.
type ClientRegistration struct {
	ClientID                string
	ClientSecret            string
	RegistrationAccessToken string
	RegistrationClientURI   string
	ClientIDIssuedAt        int64
	ClientSecretExpiresAt   int64
	ApplicationType         string
	ClientName              string
	ClientURI               string
	LogoURI                 string
	RedirectURIs            []string
	ResponseTypes           []string
	GrantTypes              []string
	TokenEndpointAuthMethod string
	Scope                   string
	Contacts                []string
	JWKSURI                 string
	JWKS                    []byte
	PolicyURI               string
	TOSURI                  string
	SoftwareID              string
	SoftwareVersion         string
}

// BackChannelStore is required by the Back Channel Logout plugin.
type BackChannelStore interface {
	ClientsForSession(ctx context.Context, sub, sid string) ([]Client, error)
}

// PARStore is required by the Pushed Authorization Request plugin.
type PARStore interface {
	StorePushedAuthRequest(ctx context.Context, clientID string, req *oidc.AuthRequest, lifetime time.Duration) (requestURI string, err error)
	GetPushedAuthRequest(ctx context.Context, requestURI string) (*oidc.AuthRequest, error)
}

// Crypto provides cryptographic operations for token encryption and signing.
//
// The base Encrypt/Decrypt methods are used for opaque token encryption.
// The optional GMCrypto interface extends this with GM/T (国密) algorithms.
type Crypto interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// GMCrypto extends Crypto with GM/T (国密) cryptographic operations.
// Implementations should use pkg/crypto for the underlying SM2/SM3/SM4/SM9 operations.
//
// Plugins can check for this interface at construction time:
//
//	if gm, ok := crypto.(storm.GMCrypto); ok { ... }
type GMCrypto interface {
	Crypto

	// SM4Encrypt encrypts plaintext using SM4 in the specified mode.
	// Supported modes: "GCM", "CCM", "CBC".
	// Returns nonce||ciphertext||tag for AEAD modes, or IV||ciphertext for CBC.
	SM4Encrypt(ctx context.Context, plaintext []byte, mode string) ([]byte, error)

	// SM4Decrypt decrypts ciphertext using SM4 in the specified mode.
	SM4Decrypt(ctx context.Context, ciphertext []byte, mode string) ([]byte, error)

	// SM2EncryptJWE encrypts plaintext using SM2+SM4-GCM JWE (GM/T 0125.3).
	// Returns JWE compact serialization.
	SM2EncryptJWE(ctx context.Context, plaintext []byte) (string, error)

	// SM2DecryptJWE decrypts an SM2+SM4 JWE compact serialization.
	SM2DecryptJWE(ctx context.Context, compact string) ([]byte, error)

	// Sign signs the payload using the algorithm associated with the given key ID.
	// Returns the compact JWS serialization.
	// For SM2, the algorithm is SGD_SM3_SM2; for SM9, SGD_SM3_SM9.
	Sign(ctx context.Context, keyID string, payload []byte) (string, error)
}

// Signer provides JWT signing capability.
// This is a simpler alternative to GMCrypto for plugins that only need signing.
type Signer interface {
	// Sign signs the payload and returns the compact JWS serialization.
	Sign(ctx context.Context, keyID string, payload []byte) (string, error)
}

// EndSessionRequest represents a parsed RP-initiated logout request.
type EndSessionRequest struct {
	UserID            string
	ClientID          string
	IDTokenHintClaims *oidc.IDTokenClaims
	RedirectURI       string
	LogoutHint        string
	UILocales         []language.Tag
}

// AdaptKeyStore converts a storm.KeyStore to a shared.KeyStore
// for use in shared verifier functions. Both return slices of
// different Key types, so each element must be adapted individually.
func AdaptKeyStore(ks KeyStore) shared.KeyStore {
	if ks == nil {
		return nil
	}
	return &keyStoreBridge{inner: ks}
}

type keyStoreBridge struct {
	inner KeyStore
}

func (b *keyStoreBridge) KeySet(ctx context.Context) ([]shared.Key, error) {
	keys, err := b.inner.KeySet(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]shared.Key, len(keys))
	for i, k := range keys {
		out[i] = &keyBridge{inner: k}
	}
	return out, nil
}

func (b *keyStoreBridge) SignatureAlgorithms(ctx context.Context) ([]string, error) {
	return b.inner.SignatureAlgorithms(ctx)
}

type keyBridge struct {
	inner Key
}

func (b *keyBridge) ID() string        { return b.inner.ID() }
func (b *keyBridge) Algorithm() string { return b.inner.Algorithm() }
func (b *keyBridge) Use() string       { return b.inner.Use() }
func (b *keyBridge) Key() jwk.Key      { return b.inner.Key() }
