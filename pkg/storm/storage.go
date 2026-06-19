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
//   - [PairwiseTransformer]   — OIDC Core §8.1 Pairwise Subject Identifiers
//
// ## Sender-constraining extensions (FAPI 2.0 / RFC 9449)
//
// These interfaces bind tokens to the client's cryptographic key or certificate,
// preventing stolen tokens from being replayed by a different party.
//
// The cnf claim is now passed directly to [TokenStore.CreateAccessToken] and
// [TokenStore.CreateAccessAndRefreshTokens] at issuance time, so storage can
// bind refresh tokens (via [RefreshTokenRequest.GetDPoPJKT]) without a separate
// post-creation store step.
//
//   - [TokenCNFLookup]            — query cnf claim for introspection / userinfo
//   - [DPoPCodeBindingStore]      — DPoP authorization code binding (RFC 9449 §7.1)
//   - [RefreshTokenRequest]       — exposes GetDPoPJKT for RFC 9449 §7.2 refresh token binding
//   - [JARMSigner]                — JWT Secured Authorization Response Mode (RFC 9101)
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

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
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

// NotificationEndpointProvider is an optional interface for clients that
// register a notification endpoint for CIBA ping delivery mode (CIBA Core 1.0 §10).
// When implemented, the SDK validates the endpoint URL for SSRF protection
// before dispatching notification callbacks.
type NotificationEndpointProvider interface {
	// NotificationEndpoint returns the client's backchannel notification URL.
	NotificationEndpoint() string
}

// FAPIProfileProvider is an optional interface that clients may implement
// to indicate they are configured for FAPI (Financial-grade API) compliance.
// Plugins that enforce FAPI-specific requirements (e.g., signed request objects
// for FAPI-CIBA) check for this interface via type assertion.
type FAPIProfileProvider interface {
	FAPIProfile() bool
}

// AccessTokenLifetimeProvider is optionally implemented by Client to control
// the lifetime of issued access tokens.
//
// When not implemented, the TokenStore decides the default lifetime.
// This is useful for multi-tenant IAM where different clients need different
// token lifetimes (e.g., high-security clients with short-lived tokens).
type AccessTokenLifetimeProvider interface {
	AccessTokenLifetime() time.Duration
}

// RateLimitClient is optionally implemented by Client to enforce per-client
// rate limiting on the token endpoint. When implemented, the token plugin
// checks the client's request rate before processing.
//
// MaxRequests: maximum number of token requests allowed within Window.
// Window: the sliding window duration (e.g. 1*time.Minute).
// If Window is zero, a default of 1 minute is used.
// If MaxRequests is zero or negative, no per-client rate limiting is applied.
type RateLimitClient interface {
	MaxTokenRequests() int
	TokenRequestWindow() time.Duration
}

// IDTokenLifetimeClient is optionally implemented by Client to control
// the lifetime of issued ID tokens. When not implemented, the plugin
// uses its default (typically 1 hour).
type IDTokenLifetimeClient interface {
	IDTokenLifetime() time.Duration
}

// DevicePollIntervalClient is optionally implemented by Client to override
// the device code / CIBA polling interval. When not implemented, the plugin
// uses its configured default (typically 5 seconds).
type DevicePollIntervalClient interface {
	DevicePollInterval() time.Duration
}

// PARLifetimeClient is optionally implemented by Client to override the
// pushed authorization request URI lifetime. When not implemented, the
// plugin uses its configured default (typically 90 seconds).
type PARLifetimeClient interface {
	PARLifetime() time.Duration
}

// AuditEvent represents a security-relevant event for audit logging.
// Storage implementations that support audit logging should implement AuditLogger.
type AuditEvent struct {
	Timestamp  time.Time      `json:"timestamp"`
	EventType  string         `json:"event_type"` // e.g. "token.issued", "auth.failed", "auth.success"
	ClientID   string         `json:"client_id"`
	Subject    string         `json:"subject"`
	GrantType  string         `json:"grant_type"`
	RemoteAddr string         `json:"remote_addr"`
	Detail     map[string]any `json:"detail,omitempty"`
}

// AuditLogger is optionally implemented by Storage to receive structured
// audit events for security-relevant operations (token issuance, authentication
// failures, etc.). Implementations should persist these events for compliance
// and incident response.
//
// When not implemented, audit events are logged via slog at INFO/WARN level
// as a fallback.
type AuditLogger interface {
	WriteAuditEvent(ctx context.Context, event AuditEvent) error
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

// SigningKeyByAlgProvider is an optional interface that a KeyStore can
// implement to support retrieving a signing key by algorithm.
// This enables per-client ID token signing algorithms.
type SigningKeyByAlgProvider interface {
	SigningKeyByAlg(ctx context.Context, alg string) (SigningKey, error)
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

// ResourceIndicator is optionally implemented by AuthRequest to expose
// the resource indicator values from the authorization request (RFC 8707).
// When present, the Token plugin merges these into the access token's audience.
type ResourceIndicator interface {
	GetResources() []string
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
	// CreateAccessToken creates an access token. The cnf map contains the
	// token's confirmation claim (e.g. jkt for DPoP, x5t#S256 for mTLS).
	// It may be nil if the token is not sender-constrained.
	CreateAccessToken(ctx context.Context, req TokenRequest, cnf map[string]any) (tokenID string, expiration time.Time, err error)

	// CreateAccessAndRefreshTokens creates an access token and a refresh token.
	// The cnf map contains the access token's confirmation claim and is also
	// used to bind the refresh token (e.g. RFC 9449 §7.2 DPoP binding).
	// currentRefreshToken is non-empty when rotating an existing refresh token.
	CreateAccessAndRefreshTokens(ctx context.Context, req TokenRequest, currentRefreshToken string, cnf map[string]any) (accessTokenID, newRefreshToken string, expiration time.Time, err error)

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
	// GetDPoPJKT returns the DPoP JWK thumbprint bound to this refresh token
	// (RFC 9449 §7.2). Returns empty string if the refresh token is not
	// DPoP-bound.
	GetDPoPJKT() string
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
//     the token's granted scopes. If you want scope-based filtering, call
//     [protocol.UserInfo.FilterByScopes] before returning; otherwise all claims
//     set on the UserInfo will be included in the response.
//   - origin is the HTTP Origin header value (for CORS), may be empty.
//   - Set the UserInfo.Subject field — this is enforced by the plugin.
//
// The SDK calls this after validating the access token. You do NOT need to
// verify the token — just populate the response.
type UserinfoStore interface {
	SetUserinfoFromToken(ctx context.Context, userinfo *protocol.UserInfo, tokenID, subject, origin string) error
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
}

// TokenExchangeRequest represents a validated token exchange request.
//
// Storage implementations receive this in CreateAccessToken (as TokenRequest).
// Type-assert to TokenExchangeRequest to detect token exchange and access
// exchange-specific fields (actor, claims, token types).
type TokenExchangeRequest interface {
	TokenRequest
	GetRequestedTokenType() protocol.TokenType
	GetSubjectTokenType() protocol.TokenType
	GetActorTokenType() protocol.TokenType
	// GetActor returns the actor's subject identifier (RFC 8693 §2.1).
	// Empty if no actor_token was provided.
	GetActor() string
	// GetActorTokenIDOrToken returns the actor token's storage ID or the raw token.
	GetActorTokenIDOrToken() string
	// GetSubjectTokenIDOrToken returns the subject token's storage ID or the raw token.
	GetSubjectTokenIDOrToken() string
	// GetSubjectTokenClaims returns private claims extracted from the subject token.
	// May be nil for opaque tokens.
	GetSubjectTokenClaims() map[string]any
	// GetActorTokenClaims returns private claims extracted from the actor token.
	// May be nil if no actor_token was provided.
	GetActorTokenClaims() map[string]any
	SetCurrentScopes(scopes []string)
	SetRequestedTokenType(tokenType protocol.TokenType)
}

// TokenExchangeExternalVerifierStorage is optionally implemented by storage
// to verify third-party (external) tokens during Token Exchange (RFC 8693 §2.1).
//
// When the subject_token or actor_token is not a token issued by this server
// (i.e., not an opaque access token, refresh token, or ID token), the SDK
// falls back to this interface for verification. This enables scenarios like:
//   - Exchanging a SAML assertion for an access token
//   - Exchanging a third-party OIDC ID token for a local token
//   - Exchanging a JWT from an external identity provider
//
// When not implemented, only tokens issued by this server are accepted.
type TokenExchangeExternalVerifierStorage interface {
	// VerifyExchangeSubjectToken verifies an external subject token.
	// Returns the token identifier (or the token itself), the subject, and
	// optional private claims extracted from the token.
	VerifyExchangeSubjectToken(ctx context.Context, token string, tokenType protocol.TokenType) (tokenIDOrToken, subject string, claims map[string]any, err error)

	// VerifyExchangeActorToken verifies an external actor token.
	// Returns the token identifier (or the token itself), the actor subject,
	// and optional private claims extracted from the token.
	VerifyExchangeActorToken(ctx context.Context, token string, tokenType protocol.TokenType) (tokenIDOrToken, actor string, claims map[string]any, err error)
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
	ApplicationType              string          `json:"application_type"`
	ClientName                   string          `json:"client_name"`
	ClientURI                    string          `json:"client_uri"`
	LogoURI                      string          `json:"logo_uri"`
	RedirectURIs                 []string        `json:"redirect_uris"`
	ResponseTypes                []string        `json:"response_types"`
	GrantTypes                   []string        `json:"grant_types"`
	TokenEndpointAuthMethod      string          `json:"token_endpoint_auth_method"`
	Scope                        string          `json:"scope"`
	Contacts                     []string        `json:"contacts"`
	JWKSURI                      string          `json:"jwks_uri"`
	JWKS                         json.RawMessage `json:"jwks"`
	PolicyURI                    string          `json:"policy_uri"`
	TOSURI                       string          `json:"tos_uri"`
	SoftwareID                   string          `json:"software_id"`
	SoftwareVersion              string          `json:"software_version"`
	PostLogoutRedirectURIs       []string        `json:"post_logout_redirect_uris"`
	BackChannelLogoutURI         string          `json:"backchannel_logout_uri"`
	SectorIdentifierURI          string          `json:"sector_identifier_uri,omitempty"`
	InitiateLoginURI             string          `json:"initiate_login_uri"`
	IDTokenSignedResponseAlg     string          `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg  string          `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc  string          `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSignedResponseAlg    string          `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoEncryptedResponseAlg string          `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoEncryptedResponseEnc string          `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestObjectSigningAlg      string          `json:"request_object_signing_alg,omitempty"`
	RequireDPoP                  bool            `json:"require_dpop,omitempty"`
	RequireMtls                  bool            `json:"require_mtls,omitempty"`
}

// ClientRegistration represents a registered client.
type ClientRegistration struct {
	ClientID                     string          `json:"client_id"`
	ClientSecret                 string          `json:"client_secret,omitempty"`
	RegistrationAccessToken      string          `json:"registration_access_token,omitempty"`
	RegistrationClientURI        string          `json:"registration_client_uri,omitempty"`
	ClientIDIssuedAt             int64           `json:"client_id_issued_at"`
	ClientSecretExpiresAt        int64           `json:"client_secret_expires_at"`
	ApplicationType              string          `json:"application_type,omitempty"`
	ClientName                   string          `json:"client_name,omitempty"`
	ClientURI                    string          `json:"client_uri,omitempty"`
	LogoURI                      string          `json:"logo_uri,omitempty"`
	RedirectURIs                 []string        `json:"redirect_uris"`
	ResponseTypes                []string        `json:"response_types,omitempty"`
	GrantTypes                   []string        `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod      string          `json:"token_endpoint_auth_method,omitempty"`
	Scope                        string          `json:"scope,omitempty"`
	Contacts                     []string        `json:"contacts,omitempty"`
	JWKSURI                      string          `json:"jwks_uri,omitempty"`
	JWKS                         json.RawMessage `json:"jwks,omitempty"`
	PolicyURI                    string          `json:"policy_uri,omitempty"`
	TOSURI                       string          `json:"tos_uri,omitempty"`
	SoftwareID                   string          `json:"software_id,omitempty"`
	SoftwareVersion              string          `json:"software_version,omitempty"`
	PostLogoutRedirectURIs       []string        `json:"post_logout_redirect_uris,omitempty"`
	BackChannelLogoutURI         string          `json:"backchannel_logout_uri,omitempty"`
	SectorIdentifierURI          string          `json:"sector_identifier_uri,omitempty"`
	InitiateLoginURI             string          `json:"initiate_login_uri,omitempty"`
	IDTokenSignedResponseAlg     string          `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg  string          `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc  string          `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSignedResponseAlg    string          `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoEncryptedResponseAlg string          `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoEncryptedResponseEnc string          `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestObjectSigningAlg      string          `json:"request_object_signing_alg,omitempty"`
	RequireDPoP                  bool            `json:"require_dpop,omitempty"`
	RequireMtls                  bool            `json:"require_mtls,omitempty"`
}

// UserInfoResponseAlgProvider is an optional interface that returns the
// client's registered userinfo_signed_response_alg value.
// When the storage implements this interface and returns a non-empty algorithm,
// the UserInfo endpoint MUST return a signed JWT (OIDC Core §5.3.2).
type UserInfoResponseAlgProvider interface {
	UserInfoResponseAlg(ctx context.Context, clientID string) (string, error)
}

// BackChannelStore is required by the Back Channel Logout plugin.
type BackChannelStore interface {
	ClientsForSession(ctx context.Context, sub, sid string) ([]Client, error)
}

// ClientSessionRecorder is an optional interface for tracking client sessions
// per subject. When implemented by the storage, the token plugin records each
// client session on token issuance so that BackChannelStore.ClientsForSession
// can find the relevant RPs to notify on logout.
type ClientSessionRecorder interface {
	RecordClientSession(subject, clientID, sid string)
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

// JARMSigner is optionally implemented by a plugin to provide JARM
// (JWT Secured Authorization Response Mode) support per RFC 9101.
//
// When implemented, the authorization response is signed as a JWT
// and returned using the requested JARM response mode (query.jwt,
// fragment.jwt, or form_post.jwt).
type JARMSigner interface {
	// SignAuthResponse signs the authorization response parameters
	// as a JWT. The ctx is used to derive the issuer URL. The params
	// map contains the response fields (code, state, etc.). The
	// clientID is used for audience validation. The signingAlg is the
	// client's preferred signing algorithm (e.g. "PS256" for FAPI);
	// if empty, the server's default is used.
	// Returns the compact JWT string.
	SignAuthResponse(ctx context.Context, params map[string]string, clientID string, signingAlg string) (string, error)
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

// ---------------------------------------------------------------------------
// CIBA (Client-Initiated Backchannel Authentication)
// ---------------------------------------------------------------------------
// OpenID Connect Client-Initiated Backchannel Authentication Core 1.0
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html

// CIBARequest represents a stored CIBA backchannel authentication request.
type CIBARequest struct {
	AuthReqID               string
	ClientID                string
	Scope                   string
	Subject                 string
	BindingMessage          string
	UserCode                string
	RequestedScopes         []string
	ExpiresAt               time.Time
	Status                  protocol.CIBAStatus
	DeliveryMode            protocol.CIBADeliveryMode
	ClientNotificationToken string
	ApprovedScopes          []string
	LastPoll                time.Time // last poll time for slow_down detection (CIBA Core 1.0 §10.1)
	Interval                int       // current polling interval in seconds
}

// CIBAStore is required by the CIBA plugin.
// It manages CIBA backchannel authentication request lifecycle.
type CIBAStore interface {
	// StoreCIBARequest persists a new CIBA authentication request.
	StoreCIBARequest(ctx context.Context, req *CIBARequest) error

	// GetCIBARequestByAuthReqID retrieves a CIBA request by its auth_req_id.
	// Returns protocol.ErrAuthorizationPending if not found.
	GetCIBARequestByAuthReqID(ctx context.Context, authReqID string) (*CIBARequest, error)

	// UpdateCIBARequestStatus updates the status of a CIBA request.
	UpdateCIBARequestStatus(ctx context.Context, authReqID string, status protocol.CIBAStatus, approvedScopes []string) error

	// GetPendingCIBARequests returns all pending CIBA requests for a given subject.
	// This is used by the approval page to show pending requests.
	GetPendingCIBARequests(ctx context.Context, subject string) ([]*CIBARequest, error)

	// UpdateCIBAPoll records the last poll time for slow_down detection.
	// Called by the token endpoint when a client polls for the CIBA grant.
	UpdateCIBAPoll(ctx context.Context, authReqID string, lastPoll time.Time) error

	// UpdateCIBAInterval increases the polling interval for slow_down compliance.
	// CIBA Core 1.0 §10.1: the interval MUST be increased by 5 seconds on slow_down.
	UpdateCIBAInterval(ctx context.Context, authReqID string, increment int) error
}

// CIBANotificationCallback is optionally implemented by the storage to receive
// notifications when a CIBA request status changes (approved/denied).
//
// CIBA Core 1.0 §10 — Ping and Push Notification Modes
// When the delivery mode is "ping", the OP MUST notify the client's
// client_notification_endpoint when the authentication completes.
// The actual HTTP POST to the client's endpoint is the storage/implementation's
// responsibility — the SDK only provides this callback hook.
//
// Implementations should:
//  1. Send an HTTP POST to the client's client_notification_endpoint
//  2. Include the client_notification_token as a Bearer token
//  3. Include the auth_req_id in the request body
//  4. Handle retries with exponential backoff
//
// Example usage:
//
//	func (s *MyStorage) OnCIBAStatusChange(ctx context.Context, req *CIBARequest) error {
//	    if req.DeliveryMode != protocol.CIBAModePing {
//	        return nil
//	    }
//	    client, _ := s.GetClientByClientID(ctx, req.ClientID)
//	    endpoint := client.NotificationEndpoint()
//	    return httpPost(ctx, endpoint, req.ClientNotificationToken, req.AuthReqID)
//	}
type CIBANotificationCallback interface {
	OnCIBAStatusChange(ctx context.Context, req *CIBARequest) error
}

// ────────────────────────────────────────────────────────────────────────────
// Per-Client Token & Claims Configuration
// ────────────────────────────────────────────────────────────────────────────

// PostLogoutRedirectURIClient is optionally implemented by Client to
// define the allowed post-logout redirect URIs (OIDC RP-Initiated Logout §2.1).
//
// When the EndSession plugin receives a post_logout_redirect_uri parameter,
// it validates against this list. If the client does not implement this
// interface, post-logout redirect is not allowed for that client.
type PostLogoutRedirectURIClient interface {
	PostLogoutRedirectURIs() []string
}

// TokenClaimsRestrictor is optionally implemented by Client to control
// which scopes are allowed in ID Token and Access Token responses.
//
// This is the kexcore-oidc equivalent of Zitadel's
// RestrictAdditionalIdTokenScopes / RestrictAdditionalAccessTokenScopes
// and Keycloak's Client Scope restrictions.
//
// Use cases:
//   - High-security clients: only allow minimal scopes in tokens
//   - Public clients: restrict to read-only scopes
//   - Service-to-service: allow broad scopes
//
// When not implemented, all requested scopes are included (subject to
// normal scope validation).
type TokenClaimsRestrictor interface {
	// RestrictIDTokenScopes filters the scopes that will be included
	// in the ID Token claims. Return a subset of the requested scopes.
	RestrictIDTokenScopes(scopes []string) []string

	// RestrictAccessTokenScopes filters the scopes that will be included
	// in the Access Token claims. Return a subset of the requested scopes.
	RestrictAccessTokenScopes(scopes []string) []string
}

// ScopeWhitelistClient is optionally implemented by Client to define
// an explicit whitelist of allowed scopes.
//
// This is the kexcore-oidc equivalent of Zitadel's IsScopeAllowed.
// When implemented, any scope requested by the client that is NOT in
// this whitelist will be silently dropped (not rejected with an error).
//
// When not implemented, all requested scopes are accepted (subject to
// server-level scope validation).
type ScopeWhitelistClient interface {
	// AllowedScopes returns the complete list of scopes this client is
	// allowed to request. Scopes not in this list will be filtered out.
	AllowedScopes() []string
}

// AccessTokenType is an enum for the access token format.
type AccessTokenType int

const (
	// AccessTokenTypeBearer uses opaque bearer tokens (default).
	AccessTokenTypeBearer AccessTokenType = iota
	// AccessTokenTypeJWT uses JWT-format access tokens (RFC 9068).
	AccessTokenTypeJWT
)

// AccessTokenFormatClient is optionally implemented by Client to specify
// the access token format (opaque bearer vs JWT).
//
// This is the kexcore-oidc equivalent of Zitadel's Client.AccessTokenType().
//
// When not implemented, the token format is determined by the storage layer.
// JWT access tokens require the storage to implement JWTAccessTokenStore.
type AccessTokenFormatClient interface {
	AccessTokenFormat() AccessTokenType
}

// JWTAccessTokenStore is optionally implemented by TokenStore to support
// JWT-format access tokens (RFC 9068).
//
// When a client requests JWT access tokens (via AccessTokenFormatClient),
// the token plugin uses this interface instead of the default opaque token flow.
type JWTAccessTokenStore interface {
	// CreateJWTAccessToken creates a JWT-format access token.
	// The returned tokenID is used for introspection/revocation lookups.
	// The returned token string is the compact JWT serialization.
	CreateJWTAccessToken(ctx context.Context, req TokenRequest, cnf map[string]any, lifetime time.Duration) (tokenID, token string, expiration time.Time, err error)
}

// UserinfoFromRequestProvider is optionally implemented by UserinfoStore
// to allow per-request customization of userinfo claims.
//
// This is the kexcore-oidc equivalent of Zitadel's CanSetUserinfoFromRequest.
// The request parameter carries the full token request context (scopes,
// audience, client info) which allows dynamic claims based on the
// specific authorization context.
//
// When implemented, the UserInfo plugin calls this instead of
// SetUserinfoFromToken for requests where richer context is needed.
type UserinfoFromRequestProvider interface {
	SetUserinfoFromRequest(ctx context.Context, userinfo *protocol.UserInfo, tokenID, subject, origin string, scopes []string) error
}

// ────────────────────────────────────────────────────────────────────────────
// Per-Client Refresh Token & Grant Type Configuration
// ────────────────────────────────────────────────────────────────────────────

// RefreshTokenLifetimeClient is optionally implemented by Client to control
// the lifetime of issued refresh tokens.
//
// This is the kexcore-oidc equivalent of Casdoor's "Refresh Token过期" setting
// and Keycloak's "Client Session Max" (refresh token is tied to session lifetime).
//
// When not implemented, the refresh token lifetime is determined by the
// storage layer (typically 24h-30d depending on the implementation).
type RefreshTokenLifetimeClient interface {
	RefreshTokenLifetime() time.Duration
}

// GrantTypeClient is optionally implemented by Client to restrict which
// OAuth 2.0 grant types are allowed for this specific client.
//
// This is the kexcore-oidc equivalent of Casdoor's "OAuth授权类型" setting
// and Keycloak's per-client "Grant Types" configuration.
//
// When implemented, the Token plugin checks the requested grant_type against
// this list BEFORE processing. If the grant type is not in the list, the
// request is rejected with unsupported_grant_type.
//
// When not implemented, all grant types enabled at the server level are allowed.
//
// Security considerations:
//   - Public clients should only allow authorization_code (with PKCE)
//   - Confidential clients can additionally use client_credentials
//   - Machine-to-machine clients can use client_credentials and jwt-bearer
//   - Device flow clients can use device_code
type GrantTypeClient interface {
	AllowedGrantTypes() []string
}

// JWTAccessTokenSigningClient is optionally implemented by Client to specify
// the signing algorithm for JWT-format access tokens.
//
// This is the kexcore-oidc equivalent of Casdoor's "Token签名算法" setting
// for access tokens in JWT format.
//
// When not implemented, the signing algorithm is determined by the server's
// KeyStore (typically RS256 or ES256).
//
// The returned algorithm MUST be one of the server's supported algorithms.
// If the algorithm is not supported, the token plugin falls back to the
// server's default.
type JWTAccessTokenSigningClient interface {
	AccessTokenSigningAlgorithm() string
}
