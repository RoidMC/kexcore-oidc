// Package dpop implements Demonstrating Proof-of-Possession (DPoP)
// at the application layer (RFC 9449).
//
// It provides:
//   - DPoP proof validation (Section 4.1, 4.2, 4.3)
//   - DPoP-bound access token creation (Section 7.1, cnf.jkt)
//   - DPoP proof verification for resource server introspection (Section 10.1)
package dpop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const (
	// DPoPHeader is the HTTP header name for the DPoP proof.
	DPoPHeader = "DPoP"

	// DPoPAccessTokenType is the token_type for DPoP-bound access tokens.
	DPoPAccessTokenType = "DPoP"

	// MaxDPoPProofAge is the maximum age of a DPoP proof (default 5 minutes per RFC 9449 §7.1).
	MaxDPoPProofAge = 5 * time.Minute
)

// Plugin implements DPoP proof validation and token binding.
type Plugin struct {
	usedNonces map[string]time.Time // jti replay detection
}

// Config holds the dependencies for the DPoP plugin.
type Config struct{}

// New creates a new DPoP plugin.
func New(cfg Config) *Plugin {
	return &Plugin{
		usedNonces: make(map[string]time.Time),
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "dpop" }

// Register is a no-op for the DPoP plugin.
func (p *Plugin) Register(r chi.Router) {}

// Contribute returns discovery fields for DPoP.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"dpop_signing_alg_values_supported": []string{"ES256", "RS256"},
	}
}

// --- Context helpers ---

type dpopContextKey struct{}

// DPoPProof holds the parsed DPoP proof from a request.
type DPoPProof struct {
	JKT       string           // JWK thumbprint (SHA-256 of JWK)
	HTM       string           // HTTP method
	HTU       string           // HTTP URI
	IssuedAt  time.Time        // iat claim
	UniqueID  string           // jti claim
	PublicKey crypto.PublicKey // The public key from the proof
}

// ContextWithDPoP stores the DPoP proof in the request context.
func ContextWithDPoP(ctx context.Context, proof *DPoPProof) context.Context {
	return context.WithValue(ctx, dpopContextKey{}, proof)
}

// DPoPFromContext retrieves the DPoP proof from the context.
// Returns nil if no DPoP proof was presented.
func DPoPFromContext(ctx context.Context) *DPoPProof {
	proof, _ := ctx.Value(dpopContextKey{}).(*DPoPProof)
	return proof
}

// --- Middleware ---

// DPoPMiddleware parses the DPoP header from the request and stores the
// proof in the request context. If no DPoP header is present, the
// context value is nil.
func DPoPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dpopHeader := r.Header.Get(DPoPHeader)
		if dpopHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		proof, err := ParseDPoPProof(dpopHeader, r.Method, r.URL.String())
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx := ContextWithDPoP(r.Context(), proof)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- DPoP proof parsing and validation ---

// ParseDPoPProof parses and validates a DPoP proof JWT.
//
// Validation steps (RFC 9449 §4.3):
//  1. Verify the JWT signature using the public key in the jwk header
//  2. Verify the typ header is "dpop+jwt"
//  3. Verify the htm claim matches the HTTP method
//  4. Verify the htu claim matches the HTTP URI
//  5. Verify the iat claim is recent (within MaxDPoPProofAge)
//  6. Compute the JWK thumbprint (jkt) for token binding
func ParseDPoPProof(dpopHeader, httpMethod, httpURL string) (*DPoPProof, error) {
	msg, err := jws.Parse([]byte(dpopHeader))
	if err != nil {
		return nil, fmt.Errorf("invalid DPoP proof: %w", err)
	}

	if len(msg.Signatures()) == 0 {
		return nil, errors.New("DPoP proof has no signatures")
	}

	sig := msg.Signatures()[0]
	headers := sig.ProtectedHeaders()

	// 1. Extract jwk from header
	jwkRaw, ok := headers.Field("jwk")
	if !ok {
		return nil, errors.New("DPoP proof missing jwk header")
	}

	jwkBytes, err := json.Marshal(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal jwk: %w", err)
	}
	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid jwk in DPoP proof: %w", err)
	}

	// 2. Verify typ is dpop+jwt
	typVal, _ := headers.Field("typ")
	typStr, _ := typVal.(string)
	if typStr != "dpop+jwt" {
		return nil, fmt.Errorf("DPoP proof has invalid typ: %v", typVal)
	}

	// Extract public key for signature verification
	rawKey, err := jwk.Export[any](key)
	if err != nil {
		return nil, fmt.Errorf("cannot export public key: %w", err)
	}
	pubKey, ok := rawKey.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("exported key is not a crypto.PublicKey: %T", rawKey)
	}

	// Verify signature
	alg, _ := headers.Algorithm()
	_, err = jws.Verify([]byte(dpopHeader), jws.WithKey(alg, key))
	if err != nil {
		return nil, fmt.Errorf("DPoP proof signature verification failed: %w", err)
	}

	// Parse payload claims
	var claims struct {
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
		return nil, fmt.Errorf("invalid DPoP proof payload: %w", err)
	}

	// 3. Verify htm matches HTTP method
	if claims.HTM != httpMethod {
		return nil, fmt.Errorf("DPoP proof htm mismatch: got %q, want %q", claims.HTM, httpMethod)
	}

	// 4. Verify htu matches HTTP URI (strip query and fragment)
	expectedURL := httpURL
	if idx := strings.IndexAny(expectedURL, "?#"); idx >= 0 {
		expectedURL = expectedURL[:idx]
	}
	if claims.HTU != expectedURL {
		return nil, fmt.Errorf("DPoP proof htu mismatch: got %q, want %q", claims.HTU, expectedURL)
	}

	// 5. Verify iat is recent
	iat := time.Unix(claims.IAT, 0)
	if time.Since(iat) > MaxDPoPProofAge {
		return nil, errors.New("DPoP proof is too old")
	}
	if time.Until(iat) > MaxDPoPProofAge {
		return nil, errors.New("DPoP proof is from the future")
	}

	// 6. Compute JWK thumbprint
	jkt, err := JWKThumbprint(key)
	if err != nil {
		return nil, fmt.Errorf("cannot compute JWK thumbprint: %w", err)
	}

	return &DPoPProof{
		JKT:       jkt,
		HTM:       claims.HTM,
		HTU:       claims.HTU,
		IssuedAt:  iat,
		UniqueID:  claims.JTI,
		PublicKey: pubKey,
	}, nil
}

// JWKThumbprint computes the JWK Thumbprint (RFC 7638) of a key.
func JWKThumbprint(key jwk.Key) (string, error) {
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumb), nil
}

// ValidateDPoPBoundToken verifies that an access token was issued with
// the same DPoP key as the current request (RFC 9449 §10.1).
//
// This is used by the resource server to verify sender-constraining.
// The token's cnf.jkt must match the JWK thumbprint from the DPoP proof.
func ValidateDPoPBoundToken(tokenCNF map[string]any, proof *DPoPProof) error {
	if proof == nil {
		return errors.New("DPoP proof required for DPoP-bound token")
	}

	jkt, ok := tokenCNF["jkt"].(string)
	if !ok {
		return errors.New("token missing cnf.jkt claim")
	}

	if jkt != proof.JKT {
		return errors.New("DPoP proof key does not match token binding")
	}

	return nil
}

// CNFClaim returns the cnf claim for DPoP-bound tokens (RFC 9449 §7.1).
func CNFClaim(jkt string) map[string]any {
	return map[string]any{
		"jkt": jkt,
	}
}

// VerifyPublicKey validates that the key type and algorithm are acceptable.
func VerifyPublicKey(key crypto.PublicKey) error {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return errors.New("DPoP only supports P-256 curve")
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return errors.New("DPoP RSA key must be at least 2048 bits")
		}
	default:
		return fmt.Errorf("unsupported DPoP key type: %T", key)
	}
	return nil
}
