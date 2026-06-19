package token

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"go.opentelemetry.io/otel/trace"
)

const validIDTokenLifetime = 1 * time.Hour

// Plugin implements the OIDC Token endpoint.
type Plugin struct {
	tokenStore             storm.TokenStore
	clientStore            storm.ClientStore
	authStore              storm.AuthStore
	deviceAuthStore        storm.DeviceAuthStore       // optional, for device_code grant
	cibaStore              storm.CIBAStore             // optional, for ciba grant
	pairwiseTransformer    storm.PairwiseTransformer   // optional, for pairwise sub
	sessionRecorder        storm.ClientSessionRecorder // optional, for back-channel logout tracking
	crypto                 storm.UniCrypto
	keyStore               storm.KeyStore
	decoder                *protocol.Decoder
	logger                 *slog.Logger
	tracer                 trace.Tracer
	auditLogger            storm.AuditLogger // optional, for structured audit events
	devicePollInterval     time.Duration     // default polling interval for device_code grant
	requireDPoP            bool              // FAPI2: require DPoP proof for all token requests
	requireMtls            bool              // FAPI2: require mTLS client certificate for all token requests
	allowPrivateIPs        bool              // allow private IPs in jwks_uri fetches (testing only)
	skipTLSCertVerify      bool              // skip TLS cert verification on outbound HTTP (testing only)
	dpopNonceSender        DPoPNonceSender   // optional, set via SetDPoPNonceSender
	invalidateRefreshOnUse bool              // RFC 6749 §10.4: invalidate old RT on refresh
	clientLimits           sync.Map          // map[string]*clientBucket — per-client rate limiting
}

// Config holds the dependencies for the Token plugin.
type Config struct {
	TokenStore  storm.TokenStore
	ClientStore storm.ClientStore
	AuthStore   storm.AuthStore
	CIBAStore   storm.CIBAStore // optional, for CIBA grant type
	Crypto      storm.UniCrypto
	KeyStore    storm.KeyStore
	Decoder     *protocol.Decoder
	Logger      *slog.Logger
	// AuditLogger receives structured audit events for token issuance and auth failures.
	// When nil, events are logged via slog as a fallback.
	AuditLogger storm.AuditLogger
	// DevicePollInterval is the default polling interval for device_code grant (default: 5s).
	DevicePollInterval time.Duration
	// RequireDPoP when true requires a valid DPoP proof for all token requests.
	// Requests without a DPoP proof are rejected with invalid_request.
	// Use this for FAPI 2.0 compliance (sender-constrained tokens via DPoP).
	RequireDPoP bool
	// RequireMtls when true requires a valid mTLS client certificate for all token requests.
	// Requests without a client certificate are rejected with invalid_request.
	// Use this for FAPI 2.0 compliance (sender-constrained tokens via mTLS).
	RequireMtls bool
	// AllowPrivateIPs disables SSRF protection for jwks_uri fetches (testing only).
	AllowPrivateIPs bool
	// SkipTLSCertVerify disables TLS certificate verification on outbound HTTP (testing only).
	SkipTLSCertVerify bool
	// SessionRecorder records client sessions for back-channel logout (optional).
	SessionRecorder storm.ClientSessionRecorder
	// InvalidateRefreshOnUse when true passes the old refresh token to
	// CreateAccessAndRefreshTokens so the storage can atomically invalidate it.
	// This is required by RFC 6749 §10.4 (refresh token rotation) and prevents
	// stolen refresh tokens from being reused. Default: false for backward
	// compatibility with conformance tests. Enable for production deployments.
	InvalidateRefreshOnUse bool
}

// DPoPNonceSender is optionally implemented by a plugin to provide
// DPoP server-provided nonce support (RFC 9449 §8).
//
// When implemented, the token endpoint includes a DPoP-Nonce header
// in successful token responses, allowing the server to rotate nonces.
type DPoPNonceSender interface {
	// WriteNonceHeader writes the DPoP-Nonce HTTP header to the response.
	WriteNonceHeader(w http.ResponseWriter)
}

// --- internal request types ---

// tokenExchangeRequest implements storm.TokenExchangeRequest for RFC 8693.
type tokenExchangeRequest struct {
	subject               string
	subjectTokenIDOrToken string
	subjectTokenType      protocol.TokenType
	actorTokenIDOrToken   string
	actorTokenType        protocol.TokenType
	actor                 string
	clientID              string
	audience              []string
	scopes                []string
	requestedTokenType    protocol.TokenType
}

func (r *tokenExchangeRequest) GetSubject() string    { return r.subject }
func (r *tokenExchangeRequest) GetAudience() []string { return r.audience }
func (r *tokenExchangeRequest) GetClientID() string   { return r.clientID }
func (r *tokenExchangeRequest) GetScopes() []string   { return r.scopes }
func (r *tokenExchangeRequest) GetRequestedTokenType() protocol.TokenType {
	return r.requestedTokenType
}
func (r *tokenExchangeRequest) GetSubjectTokenType() protocol.TokenType {
	return r.subjectTokenType
}
func (r *tokenExchangeRequest) GetActorTokenType() protocol.TokenType {
	return r.actorTokenType
}
func (r *tokenExchangeRequest) SetCurrentScopes(scopes []string) { r.scopes = scopes }
func (r *tokenExchangeRequest) SetRequestedTokenType(tt protocol.TokenType) {
	r.requestedTokenType = tt
}

// deviceTokenRequest implements storm.TokenRequest for device_code grant.
type deviceTokenRequest struct {
	subject  string
	clientID string
	scopes   []string
}

func (r *deviceTokenRequest) GetSubject() string    { return r.subject }
func (r *deviceTokenRequest) GetClientID() string   { return r.clientID }
func (r *deviceTokenRequest) GetScopes() []string   { return r.scopes }
func (r *deviceTokenRequest) GetAudience() []string { return []string{r.clientID} }

// jwtBearerTokenRequest implements storm.TokenRequest for jwt-bearer grant (RFC 7523 §2.1).
type jwtBearerTokenRequest struct {
	subject  string
	clientID string
	scopes   []string
	audience []string
}

func (r *jwtBearerTokenRequest) GetSubject() string    { return r.subject }
func (r *jwtBearerTokenRequest) GetClientID() string   { return r.clientID }
func (r *jwtBearerTokenRequest) GetScopes() []string   { return r.scopes }
func (r *jwtBearerTokenRequest) GetAudience() []string { return r.audience }

// cibaTokenRequest implements storm.TokenRequest for CIBA grant type.
type cibaTokenRequest struct {
	subject  string
	clientID string
	scopes   []string
}

func (r *cibaTokenRequest) GetSubject() string    { return r.subject }
func (r *cibaTokenRequest) GetClientID() string   { return r.clientID }
func (r *cibaTokenRequest) GetScopes() []string   { return r.scopes }
func (r *cibaTokenRequest) GetAudience() []string { return []string{r.clientID} }

// --- internal interfaces (capability detection) ---

type idTokenClaimsExtender interface {
	ExtraIDTokenClaims() map[string]any
}

type idTokenEncryptionClient interface {
	IDTokenEncryptionAlg() string
	IDTokenEncryptionEnc() string
}

type tokenEncryptionKeyProvider interface {
	TokenEncryptionKey() []byte
}

type sm2EncryptionKeyProvider interface {
	SM2TokenEncryptionPublicKey() interface{}
}

type sm9EncryptionKeyProvider interface {
	SM9TokenEncryptionKey() protocol.SM9EncryptKey
}

type clientCredentialsStore interface {
	ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (storm.TokenRequest, error)
}

// resourceAwareRequest wraps a TokenRequest to merge RFC 8707 resource
// indicator values into GetAudience(). This ensures the access token's
// aud claim includes the resource parameter values from the authorization request.
type resourceAwareRequest struct {
	storm.TokenRequest
	resources []string
}

func (r *resourceAwareRequest) GetAudience() []string {
	base := r.TokenRequest.GetAudience()
	if len(r.resources) == 0 {
		return base
	}
	// Merge: deduplicate base + resources
	seen := make(map[string]bool, len(base)+len(r.resources))
	merged := make([]string, 0, len(base)+len(r.resources))
	for _, v := range base {
		if !seen[v] {
			seen[v] = true
			merged = append(merged, v)
		}
	}
	for _, v := range r.resources {
		if !seen[v] {
			seen[v] = true
			merged = append(merged, v)
		}
	}
	return merged
}
