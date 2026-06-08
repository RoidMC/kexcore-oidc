package storm

import (
	"context"
	"encoding/json"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"golang.org/x/text/language"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
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

// ScopeValidationClient is an optional interface that clients may implement
// to control whether scope validation is strict (error on unsupported scopes)
// or lenient (silently strip unsupported scopes).
//
// When not implemented, the default behavior is lenient (strip).
type ScopeValidationClient interface {
	Client
	// StrictScopeValidation returns true to reject unsupported scopes with
	// an error, or false (or not implemented) to silently strip them.
	StrictScopeValidation() bool
}

// KeyStore provides cryptographic key access.
// It extends protocol.KeyStore with SigningKey for OP-side token signing.
type KeyStore interface {
	KeySet(ctx context.Context) ([]protocol.Key, error)
	SignatureAlgorithms(ctx context.Context) ([]string, error)
	SigningKey(ctx context.Context) (SigningKey, error)
}

// Key is an alias for protocol.Key.
// GM/T keys should additionally satisfy protocol.GMJWKProvider
// for JWKS publication of SM2/SM9 keys that jwx cannot represent.
type Key = protocol.Key

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
	CreateAuthRequest(ctx context.Context, req *protocol.AuthRequest, userID string) (AuthRequest, error)
	AuthRequestByID(ctx context.Context, id string) (AuthRequest, error)
	AuthRequestByCode(ctx context.Context, code string) (AuthRequest, error)
	SaveAuthCode(ctx context.Context, id, code string) error
	DeleteAuthRequest(ctx context.Context, id string) error
}

// AutoCompleteAuthRequest is an optional interface that AuthStore can
// implement to support auto-completing auth requests without going
// through the login UI. This is used when prompt=none is requested
// and an active session exists (OIDC Core §3.1.2.6).
//
// When implemented, the Authorization plugin calls CompleteAuthRequest
// instead of redirecting to the login UI, ensuring the auth_time
// claim reflects the original authentication time.
type AutoCompleteAuthRequest interface {
	CompleteAuthRequest(ctx context.Context, id string, subject string, authTime time.Time, sid string) error
}

// CodeReuseDetector is an optional interface that storage can implement
// to detect authorization code reuse and revoke associated tokens.
// Per RFC 6749 §4.1.2: "If an authorization code is used more than once,
// the authorization server MUST revoke all tokens issued based on that
// authorization code."
type CodeReuseDetector interface {
	// TrackTokenForAuthRequest records that a token was issued for an auth request.
	TrackTokenForAuthRequest(authRequestID, tokenID string)
	// RevokeTokensForUsedCode revokes all tokens issued for a used code.
	// Returns the auth request ID if found, or empty string if the code was not used.
	RevokeTokensForUsedCode(code string) string
}

// AuthRequest represents an in-flight authorization request.
type AuthRequest interface {
	GetID() string
	GetACR() string
	GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetCodeChallenge() *protocol.CodeChallenge
	GetNonce() string
	GetRedirectURI() string
	GetResponseType() protocol.ResponseType
	GetResponseMode() protocol.ResponseMode
	GetScopes() []string
	GetState() string
	GetSubject() string
	GetClaims() *protocol.ClaimsRequest
	GetSID() string
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

// ClientKeyProvider is optionally implemented by Client to provide
// the client's public key for ID token encryption (JWE).
//
// When implemented, the Token plugin uses the returned key to encrypt
// the ID token using the algorithm specified by IDTokenEncryptionAlg/Enc.
//
// Returning a jwk.Key ensures the JWE header includes the correct "kid".
// Raw key types (*rsa.PublicKey, *ecdh.PublicKey, []byte) are also accepted
// but will not produce a "kid" in the JWE header.
//
// When not implemented, ID token encryption is only available for
// algorithms that use the server's UniCrypto (dir, SM2, SM9).
type ClientKeyProvider interface {
	// ClientEncryptionKey returns the key used to encrypt ID tokens.
	// Preferred type: jwk.Key (includes kid for JWE header).
	// Also accepted: *rsa.PublicKey, *ecdh.PublicKey, []byte.
	ClientEncryptionKey() interface{}
}

// RefreshTokenRequest extends TokenRequest for refresh token operations.
type RefreshTokenRequest interface {
	TokenRequest
	GetAMR() []string
	GetAuthTime() time.Time
	GetCodeChallenge() *protocol.CodeChallenge
	GetNonce() string
	GetID() string
	SetCurrentScopes(scopes []string)
}

// IntrospectStore is required by the Introspection plugin.
type IntrospectStore interface {
	SetIntrospectionFromToken(ctx context.Context, resp *protocol.IntrospectionResponse, tokenID, subject, clientID string) error
}

// UserinfoStore is required by the UserInfo plugin.
type UserinfoStore interface {
	SetUserinfoFromToken(ctx context.Context, userinfo *protocol.UserInfo, tokenID, subject, origin string) error
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
	SetUserinfoFromTokenExchangeRequest(ctx context.Context, userinfo *protocol.UserInfo, req TokenExchangeRequest) error
}

// TokenExchangeRequest represents a validated token exchange request.
type TokenExchangeRequest interface {
	TokenRequest
	GetRequestedTokenType() protocol.TokenType
	GetSubjectTokenType() protocol.TokenType
	GetActorTokenType() protocol.TokenType
	SetCurrentScopes(scopes []string)
	SetRequestedTokenType(tokenType protocol.TokenType)
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
	ApplicationType         string          `json:"application_type"`
	ClientName              string          `json:"client_name"`
	ClientURI               string          `json:"client_uri"`
	LogoURI                 string          `json:"logo_uri"`
	RedirectURIs            []string        `json:"redirect_uris"`
	ResponseTypes           []string        `json:"response_types"`
	GrantTypes              []string        `json:"grant_types"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	Scope                   string          `json:"scope"`
	Contacts                []string        `json:"contacts"`
	JWKSURI                 string          `json:"jwks_uri"`
	JWKS                    json.RawMessage `json:"jwks"`
	PolicyURI               string          `json:"policy_uri"`
	TOSURI                  string          `json:"tos_uri"`
	SoftwareID              string          `json:"software_id"`
	SoftwareVersion         string          `json:"software_version"`
	PostLogoutRedirectURIs  []string        `json:"post_logout_redirect_uris"`
	BackChannelLogoutURI    string          `json:"backchannel_logout_uri"`
}

// ClientRegistration represents a registered client.
type ClientRegistration struct {
	ClientID                string          `json:"client_id"`
	ClientSecret            string          `json:"client_secret,omitempty"`
	RegistrationAccessToken string          `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string          `json:"registration_client_uri,omitempty"`
	ClientIDIssuedAt        int64           `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64           `json:"client_secret_expires_at"`
	ApplicationType         string          `json:"application_type,omitempty"`
	ClientName              string          `json:"client_name,omitempty"`
	ClientURI               string          `json:"client_uri,omitempty"`
	LogoURI                 string          `json:"logo_uri,omitempty"`
	RedirectURIs            []string        `json:"redirect_uris"`
	ResponseTypes           []string        `json:"response_types,omitempty"`
	GrantTypes              []string        `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string          `json:"scope,omitempty"`
	Contacts                []string        `json:"contacts,omitempty"`
	JWKSURI                 string          `json:"jwks_uri,omitempty"`
	JWKS                    json.RawMessage `json:"jwks,omitempty"`
	PolicyURI               string          `json:"policy_uri,omitempty"`
	TOSURI                  string          `json:"tos_uri,omitempty"`
	SoftwareID              string          `json:"software_id,omitempty"`
	SoftwareVersion         string          `json:"software_version,omitempty"`
	PostLogoutRedirectURIs  []string        `json:"post_logout_redirect_uris,omitempty"`
	BackChannelLogoutURI    string          `json:"backchannel_logout_uri,omitempty"`
}

// BackChannelStore is required by the Back Channel Logout plugin.
type BackChannelStore interface {
	ClientsForSession(ctx context.Context, sub, sid string) ([]Client, error)
}

// PARStore is required by the Pushed Authorization Request plugin.
type PARStore interface {
	StorePushedAuthRequest(ctx context.Context, clientID string, req *protocol.AuthRequest, lifetime time.Duration) (requestURI string, err error)
	GetPushedAuthRequest(ctx context.Context, requestURI string) (*protocol.AuthRequest, error)
}

// UniCrypto provides a unified cryptographic interface for all algorithm families.
//
// This interface abstracts away the differences between standard algorithms
// (RSA, ECDSA, AES, SHA) and Chinese national standards (SM2, SM3, SM4).
// Implementations can be backed by software libraries or hardware (HSM/KMS).
//
// Usage:
//
//	crypto.Hash(ctx, "RS256", data)       // SHA-256
//	crypto.Hash(ctx, "SGD_SM3_SM2", data) // SM3
//	crypto.Encrypt(ctx, plaintext)         // default encryption
//	crypto.Sign(ctx, keyID, payload)       // sign with algorithm from key
type UniCrypto interface {
	// --- Hash ---
	// Hash computes the hash of data using the algorithm identified by sigAlgorithm.
	// The sigAlgorithm parameter follows JWA naming conventions:
	//   - "RS256", "ES256", "PS256" → SHA-256
	//   - "RS384", "ES384", "PS384" → SHA-384
	//   - "RS512", "ES512", "PS512", "EdDSA" → SHA-512
	//   - "SGD_SM3_SM2", "SGD_SM3_SM9" → SM3
	// Returns the raw hash bytes (not base64 encoded).
	Hash(ctx context.Context, sigAlgorithm string, data []byte) ([]byte, error)

	// --- Signing ---
	// Sign signs the payload using the algorithm associated with the given key ID.
	// Returns the compact JWS serialization.
	Sign(ctx context.Context, keyID string, payload []byte) (string, error)

	// --- Symmetric Encryption ---
	// Encrypt encrypts plaintext using the configured algorithm.
	// For standard: AES-GCM. For GM: SM4-GCM.
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext using the configured algorithm.
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)

	// --- Algorithm Query ---
	// AlgorithmSuite returns the current algorithm suite identifier.
	// Examples: "RSA+SHA256+AES", "SM2+SM3+SM4", "ECDSA+SHA256+AES"
	AlgorithmSuite() string
}

// Signer provides JWT signing capability.
// This is a simpler alternative to UniCrypto for plugins that only need signing.
type Signer interface {
	// Sign signs the payload and returns the compact JWS serialization.
	Sign(ctx context.Context, keyID string, payload []byte) (string, error)
}

// EndSessionRequest represents a parsed RP-initiated logout request.
type EndSessionRequest struct {
	UserID             string
	ClientID           string
	IDTokenHintClaims  *protocol.IDTokenClaims
	RedirectURI        string
	State              string
	LogoutHint         string
	UILocales          []language.Tag
	InvalidRedirectURI bool // true when post_logout_redirect_uri was provided but not registered
}
