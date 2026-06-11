// StormEngine storage interfaces.
//
// Storage is the data layer of StormEngine. You implement these interfaces
// to connect the OIDC protocol engine to your database, LDAP, or any
// other backend. The SDK never binds to a specific storage technology.
//
// # How it works
//
// Engine discovers your storage's capabilities via Go type assertions.
// Each plugin declares which interfaces it needs (via Requires()), and
// Engine checks at Build time that your storage satisfies them.
// If a required interface is missing, Build() panics with a clear error
// telling you exactly which methods to add.
//
// # Implementation guide
//
// The interfaces below are grouped by how much OIDC functionality they unlock.
// Start with Core, add Standard/Extended as needed.
//
// ## Core — required for a working OIDC authorization code flow
//
//   - [Storage]           (base)         — ClientStore + KeyStore + Health
//   - [ClientStore]       (always)       — client lookup + secret verification
//   - [KeyStore]          (always)       — JWKS publication + signing key access
//   - [AuthStore]         (authorization + token plugins) — auth request CRUD + code management
//   - [TokenStore]        (token plugin) — access/refresh token creation + lookup
//   - [UserinfoStore]     (userinfo plugin) — populate UserInfo from token
//
// These 6 interfaces are the minimum for a working authorization code flow
// with UserInfo endpoint. The example at example/storm-server/storage/
// provides a reference implementation (~800 lines for Core).
//
// ## Standard — enable common OIDC features
//
//   - [IntrospectStore]       — RFC 7662 Token Introspection
//   - [RevocationStore]       — RFC 7009 Token Revocation
//   - [SessionStore]          — Session management (RP-Initiated Logout)
//   - [AutoCompleteAuthRequest] — prompt=none support (OIDC Core §3.1.2.6)
//   - [CodeReuseDetector]     — RFC 6749 §4.1.2 code reuse detection
//
// ## Extended — advanced features, implement as needed
//
//   - [DCRStore]              — RFC 7591 Dynamic Client Registration
//   - [DeviceAuthStore]       — RFC 8628 Device Authorization Grant
//   - [PARStore]              — RFC 9126 Pushed Authorization Requests
//   - [BackChannelStore]      — OIDC Back-Channel Logout
//   - [ClientCredentialsStore] — OAuth 2.0 Client Credentials Grant
//   - [JWTProfileStore]       — RFC 7523 JWT Bearer Grant
//   - [TokenExchangeStore]    — RFC 8693 Token Exchange
//   - [TokenCNFStore]         — RFC 8705/9449 Token Binding (cnf claim)
//   - [TokenScopeProvider]    — Scope-based UserInfo claim filtering
//   - [PairwiseTransformer]   — OIDC Core §8.1 Pairwise Subject Identifiers
//
// ## Optional extensions on Client
//
// Clients can implement additional interfaces for per-client behavior:
//
//   - [ScopeValidationClient]  — strict vs lenient scope validation
//   - [ClientKeyProvider]      — ID token encryption (JWE)
//   - [IDTokenLifetimeProvider] — custom ID token lifetime
//
// See example/storm-server/storage/ for a complete reference implementation.
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
//
// At minimum, your Storage must embed ClientStore and KeyStore,
// and provide a Health() method. All other interfaces are discovered
// via type assertion — implement them to enable additional plugins.
type Storage interface {
	// ClientStore provides client lookup and credential verification.
	// Required by: authorization, token, userinfo, DCR, device, PAR plugins.
	ClientStore

	// KeyStore provides JWKS and signing key access.
	// Required by: token, keys, authorization (Request Object verification) plugins.
	KeyStore

	// Health is used by the /ready probe.
	// Return nil when the storage backend is reachable.
	Health(ctx context.Context) error
}

// ClientStore provides client lookup and credential verification.
// Required by: authorization, token, userinfo, DCR, device, PAR plugins.
//
// Implementation notes:
//   - GetClientByClientID: return a Client that implements at least the base Client interface.
//     For additional behavior, return a Client that also implements optional interfaces
//     like ScopeValidationClient, RedirectURIClient, etc.
//   - AuthorizeClientIDSecret: verify client_secret for confidential clients.
//     Return nil if valid, error if invalid. Used for client_secret_basic and client_secret_post.
//
// Security considerations:
//   - AuthorizeClientIDSecret: secret comparison MUST use constant-time comparison
//     (e.g., crypto/subtle.ConstantTimeCompare or bcrypt.CompareHashAndPassword)
//     to prevent timing-based side-channel attacks that could leak secret validity.
//     NEVER use == or strings.Compare for secret verification.
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
//
// Implementation notes:
//   - KeySet: return all public keys as JWKS (for /jwks endpoint and token verification).
//     Each key must implement protocol.Key (jwk.Key with KeyID and Algorithm).
//   - SignatureAlgorithms: return the list of supported signing algorithms (e.g. ["RS256", "ES256"]).
//     Used by discovery document.
//   - SigningKey: return the current signing key + algorithm for token signing.
//     The SDK uses this to sign ID tokens and access tokens (if JWT).
//     Rotate keys by changing what this returns — old keys stay in KeySet for verification.
//
// Security considerations:
//   - Key rotation: when rotating signing keys, KeySet MUST continue to return
//     old keys until all tokens signed with them have expired. Removing old keys
//     prematurely will cause signature verification failures for existing tokens.
//   - KeySet should return keys with explicit "kid" and "alg" to prevent
//     algorithm confusion attacks (RFC 7517 §4.4).
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

// AuthStore is required by the Authorization and Token plugins.
// It manages the lifecycle of authorization requests and authorization codes.
//
// Implementation notes:
//   - CreateAuthRequest: store the auth request, return a handle (AuthRequest) with a unique ID.
//     The returned AuthRequest must satisfy the AuthRequest interface (16 getters).
//   - AuthRequestByID: look up by the handle ID (used during login UI flow).
//   - AuthRequestByCode: look up by authorization code (used during token exchange).
//     After a successful lookup, the code should be invalidated (one-time use).
//   - SaveAuthCode: associate an authorization code string with an auth request ID.
//   - DeleteAuthRequest: clean up after the auth request is fully processed.
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

// TokenStore is required by the Token, UserInfo, Introspection, and Revocation plugins.
// It manages access token and refresh token creation and lookup.
//
// Implementation notes:
//   - CreateAccessToken: store the token with subject, clientID, scopes, audience.
//     Return a unique tokenID (opaque string, used as key for other stores) and expiration time.
//   - CreateAccessAndRefreshTokens: same as CreateAccessToken but also issue a refresh token.
//     currentRefreshToken is empty for first issuance; non-empty when rotating (delete old RT first).
//   - TokenRequestByRefreshToken: look up the original token request by refresh token string.
//     The returned RefreshTokenRequest carries the original subject, scopes, audience, etc.
//
// The tokenID you return is the key used by TokenCNFStore, IntrospectStore,
// and UserinfoStore to look up token metadata. It can be a UUID, database
// primary key, or any opaque string — the SDK never inspects it.
type TokenStore interface {
	CreateAccessToken(ctx context.Context, req TokenRequest) (tokenID string, expiration time.Time, err error)
	CreateAccessAndRefreshTokens(ctx context.Context, req TokenRequest, currentRefreshToken string) (accessTokenID, newRefreshToken string, expiration time.Time, err error)
	TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (RefreshTokenRequest, error)
}

// DPoPCodeBindingStore is optionally implemented by AuthStore to support
// DPoP authorization code binding (RFC 9449 §7.1).
//
// When the authorization request includes a DPoP proof (dpop_jkt parameter),
// the authorization plugin stores the JWK thumbprint. The token plugin then
// verifies that the DPoP proof presented during token exchange matches the
// stored thumbprint.
type DPoPCodeBindingStore interface {
	// SetAuthRequestDPoPJKT stores the DPoP JWK thumbprint for an authorization request.
	SetAuthRequestDPoPJKT(ctx context.Context, authRequestID string, jkt string) error
	// GetAuthRequestDPoPJKT retrieves the DPoP JWK thumbprint for an authorization request.
	GetAuthRequestDPoPJKT(ctx context.Context, authRequestID string) (string, error)
}

// TokenCNFStore is an optional extension of TokenStore that supports
// storing the cnf (confirmation) claim for certificate-bound or
// DPoP-bound access tokens (RFC 8705 §3.1, RFC 9449 §7.1).
type TokenCNFStore interface {
	SetTokenCNF(ctx context.Context, tokenID string, cnf map[string]any) error
}

// TokenCNFLookup is an optional extension that allows querying the stored
// cnf (confirmation) claim for a token. Used by the UserInfo and
// Introspection endpoints to verify sender-constrained tokens.
//
// If your storage implements TokenCNFStore, you should also implement
// TokenCNFLookup so that protected resource endpoints can verify the binding.
type TokenCNFLookup interface {
	TokenCNF(ctx context.Context, tokenID string) (map[string]any, error)
}

// TokenClientProvider is optionally implemented by storage to return
// the client_id that a token was issued to. Used by the UserInfo endpoint
// to populate the "aud" claim in JWT responses (OIDC Core §5.3.2).
type TokenClientProvider interface {
	TokenClientID(ctx context.Context, tokenID string) (string, error)
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

// ClientJWKSProvider is optionally implemented by Client to provide
// the client's public JWKS keys for signature verification.
//
// Used by the JWT Bearer Grant (RFC 7523 §2.1) to verify the client's
// signed assertion. The returned keys should include use=sig keys.
//
// When not implemented, the client cannot use the JWT Bearer Grant.
type ClientJWKSProvider interface {
	// ClientJWKS returns the client's public keys for signature verification.
	ClientJWKS() []jwk.Key
}

// ClientJWKSURIProvider is optionally implemented by Client to provide
// the client's jwks_uri for fetching fresh keys.
//
// When the RP rotates its keys, the OP should fetch fresh keys from
// the jwks_uri instead of using cached keys from registration.
type ClientJWKSURIProvider interface {
	// ClientJWKSURI returns the client's jwks_uri endpoint.
	ClientJWKSURI() string
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

// UserinfoStore is required by the UserInfo plugin (OIDC Core §5.3).
//
// Implementation notes:
//   - SetUserinfoFromToken receives a tokenID (from TokenStore) and the subject claim.
//     Look up the user by subject, then populate the UserInfo fields based on
//     the token's granted scopes. For scope-based filtering, you can either:
//     (a) filter here based on token scopes, or
//     (b) implement [TokenScopeProvider] and let the plugin filter automatically.
//   - origin is the HTTP Origin header value (for CORS), may be empty.
//   - Set the UserInfo.Subject field — this is enforced by the plugin.
//
// The SDK calls this after validating the access token. You do NOT need to
// verify the token — just populate the response.
type UserinfoStore interface {
	SetUserinfoFromToken(ctx context.Context, userinfo *protocol.UserInfo, tokenID, subject, origin string) error
}

// TokenScopeProvider is an optional extension of UserinfoStore or TokenStore
// that returns the scopes associated with a token. When implemented, the
// UserInfo plugin uses it to filter standard OIDC claims by scope (OIDC Core §5.4).
type TokenScopeProvider interface {
	TokenScopes(ctx context.Context, tokenID string) ([]string, error)
}

// RevocationStore is required by the Revocation plugin.
//
// Security considerations:
//   - RevokeToken: when revoking a refresh token, you MUST also revoke all associated
//     access tokens (RFC 7009 §2.1). Implementations should perform cascade revocation
//     within a single transaction to avoid partial revocation states.
//   - GetRefreshTokenInfo: the returned tokenID should be the same identifier used
//     in TokenStore, so that Revocation can invalidate all related tokens atomically.
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
	// GetDeviceAuthorizationByUserCode looks up a device authorization by user code.
	// Used by the verification page (GET /device) to display authorization details.
	GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*DeviceAuthorizationState, error)
	// ApproveDeviceAuthorization marks a device authorization as approved by the end-user.
	// subject is the authenticated user's identifier.
	ApproveDeviceAuthorization(ctx context.Context, userCode, subject string) error
	// DenyDeviceAuthorization marks a device authorization as denied by the end-user.
	DenyDeviceAuthorization(ctx context.Context, userCode string) error
	// UpdateDeviceAuthorizationPoll records the last poll time for slow_down detection.
	// Called by the token endpoint when a client polls for the device code grant.
	UpdateDeviceAuthorizationPoll(ctx context.Context, clientID, deviceCode string, lastPoll time.Time) error
	// UpdateDeviceAuthorizationInterval increases the polling interval for slow_down compliance.
	// RFC 8628 §3.4: the interval MUST be increased by 5 seconds on slow_down.
	UpdateDeviceAuthorizationInterval(ctx context.Context, clientID, deviceCode string, increment int) error
}

// DeviceAuthorizationState represents the current state of a device auth flow.
type DeviceAuthorizationState struct {
	DeviceCode string
	ClientID   string
	UserCode   string
	Subject    string
	Scopes     []string
	Done       bool
	Denied     bool
	Expires    time.Time
	LastPoll   time.Time // last poll time for slow_down detection (RFC 8628 §3.4)
	Interval   int       // current polling interval in seconds
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
	ApplicationType             string          `json:"application_type"`
	ClientName                  string          `json:"client_name"`
	ClientURI                   string          `json:"client_uri"`
	LogoURI                     string          `json:"logo_uri"`
	RedirectURIs                []string        `json:"redirect_uris"`
	ResponseTypes               []string        `json:"response_types"`
	GrantTypes                  []string        `json:"grant_types"`
	TokenEndpointAuthMethod     string          `json:"token_endpoint_auth_method"`
	Scope                       string          `json:"scope"`
	Contacts                    []string        `json:"contacts"`
	JWKSURI                     string          `json:"jwks_uri"`
	JWKS                        json.RawMessage `json:"jwks"`
	PolicyURI                   string          `json:"policy_uri"`
	TOSURI                      string          `json:"tos_uri"`
	SoftwareID                  string          `json:"software_id"`
	SoftwareVersion             string          `json:"software_version"`
	PostLogoutRedirectURIs      []string        `json:"post_logout_redirect_uris"`
	BackChannelLogoutURI        string          `json:"backchannel_logout_uri"`
	SectorIdentifierURI         string          `json:"sector_identifier_uri,omitempty"`
	InitiateLoginURI            string          `json:"initiate_login_uri"`
	IDTokenEncryptedResponseAlg string          `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc string          `json:"id_token_encrypted_response_enc,omitempty"`
}

// ClientRegistration represents a registered client.
type ClientRegistration struct {
	ClientID                    string          `json:"client_id"`
	ClientSecret                string          `json:"client_secret,omitempty"`
	RegistrationAccessToken     string          `json:"registration_access_token,omitempty"`
	RegistrationClientURI       string          `json:"registration_client_uri,omitempty"`
	ClientIDIssuedAt            int64           `json:"client_id_issued_at"`
	ClientSecretExpiresAt       int64           `json:"client_secret_expires_at"`
	ApplicationType             string          `json:"application_type,omitempty"`
	ClientName                  string          `json:"client_name,omitempty"`
	ClientURI                   string          `json:"client_uri,omitempty"`
	LogoURI                     string          `json:"logo_uri,omitempty"`
	RedirectURIs                []string        `json:"redirect_uris"`
	ResponseTypes               []string        `json:"response_types,omitempty"`
	GrantTypes                  []string        `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod     string          `json:"token_endpoint_auth_method,omitempty"`
	Scope                       string          `json:"scope,omitempty"`
	Contacts                    []string        `json:"contacts,omitempty"`
	JWKSURI                     string          `json:"jwks_uri,omitempty"`
	JWKS                        json.RawMessage `json:"jwks,omitempty"`
	PolicyURI                   string          `json:"policy_uri,omitempty"`
	TOSURI                      string          `json:"tos_uri,omitempty"`
	SoftwareID                  string          `json:"software_id,omitempty"`
	SoftwareVersion             string          `json:"software_version,omitempty"`
	PostLogoutRedirectURIs      []string        `json:"post_logout_redirect_uris,omitempty"`
	BackChannelLogoutURI        string          `json:"backchannel_logout_uri,omitempty"`
	SectorIdentifierURI         string          `json:"sector_identifier_uri,omitempty"`
	InitiateLoginURI            string          `json:"initiate_login_uri,omitempty"`
	IDTokenEncryptedResponseAlg string          `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc string          `json:"id_token_encrypted_response_enc,omitempty"`
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

// PairwiseTransformer is an optional interface that transforms subjects
// into pairwise identifiers (OIDC Core §8.1). If the storage implements
// this interface, the token plugin will automatically apply pairwise
// transformation when creating tokens for clients that require it.
type PairwiseTransformer interface {
	// Transform converts a real subject into a pairwise subject for a given client.
	// The same (clientID, subject) pair must always produce the same result.
	Transform(clientID, subject string) string

	// IsPairwiseClient returns true if the client uses pairwise subject identifiers.
	IsPairwiseClient(clientID string) bool
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
