package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const (
	// Header is the HTTP header name for the DPoP proof.
	Header = "DPoP"

	// AccessTokenType is the token_type for DPoP-bound access tokens.
	AccessTokenType = "DPoP"

	// MaxProofAge is the maximum age of a DPoP proof (default 5 minutes per RFC 9449 §7.1).
	MaxProofAge = 5 * time.Minute
)

// ParseProof parses and validates a DPoP proof JWT (RFC 9449 §4.3).
func ParseProof(dpopHeader, httpMethod, httpURL string) (*Proof, error) {
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
	if time.Since(iat) > MaxProofAge {
		return nil, errors.New("DPoP proof is too old")
	}
	if time.Until(iat) > MaxProofAge {
		return nil, errors.New("DPoP proof is from the future")
	}

	// 6. Compute JWK thumbprint
	jkt, err := JWKThumbprint(key)
	if err != nil {
		return nil, fmt.Errorf("cannot compute JWK thumbprint: %w", err)
	}

	return &Proof{
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

// ValidateBoundToken verifies that an access token was issued with
// the same DPoP key as the current request (RFC 9449 §10.1).
func ValidateBoundToken(tokenCNF map[string]any, proof *Proof) error {
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
