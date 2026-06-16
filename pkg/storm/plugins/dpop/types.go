package dpop

import (
	"time"
)

// Proof holds the parsed DPoP proof from a request.
type Proof struct {
	JKT       string      // JWK thumbprint (SHA-256 of JWK)
	HTM       string      // HTTP method
	HTU       string      // HTTP URI
	ATH       string      // access token hash (base64url(SHA-256(access_token)))
	IssuedAt  time.Time   // iat claim
	UniqueID  string      // jti claim
	PublicKey interface{} // The public key from the proof (crypto.PublicKey)
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
