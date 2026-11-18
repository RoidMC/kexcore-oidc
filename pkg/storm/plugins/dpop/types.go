package dpop

import (
	"context"
	"time"
)

// Proof holds the parsed DPoP proof from a request.
type Proof struct {
	JKT       string      // JWK thumbprint (SHA-256 of JWK)
	HTM       string      // HTTP method
	HTU       string      // HTTP URI
	ATH       string      // access token hash (base64url(SHA-256(access_token)))
	Nonce     string      // server-provided nonce (RFC 9449 §8)
	IssuedAt  time.Time   // iat claim
	UniqueID  string      // jti claim
	PublicKey interface{} // The public key from the proof (crypto.PublicKey)
}

// NonceStore persists server-provided nonces across instances.
type NonceStore interface {
	StoreNonce(ctx context.Context, nonce string, expiresAt time.Time) error
	// ConsumeNonce returns false when the nonce is unknown, expired or already used.
	ConsumeNonce(ctx context.Context, nonce string) (bool, error)
}

// ReplayStore records DPoP proof jti values so replays are detected across
// multiple instances.
type ReplayStore interface {
	// SeenJTI records jti and reports whether it had already been seen.
	SeenJTI(ctx context.Context, jti string, expiresAt time.Time) (bool, error)
}

// NoncePolicy lets storage require server-provided DPoP nonces (RFC 9449 §8).
// FAPI 2.0 deployments typically enable this.
type NoncePolicy interface {
	RequireDPoPNonce() bool
}

// JWKThumbprint returns the JWK thumbprint (cnf.jkt value).
// Implements shared.DPoPProof interface.
func (p *Proof) JWKThumbprint() string {
	return p.JKT
}

// AccessTokenHash returns the ath claim from the DPoP proof.
// Implements shared.DPoPProof interface.
func (p *Proof) AccessTokenHash() string {
	return p.ATH
}
