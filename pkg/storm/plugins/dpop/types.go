package dpop

import (
	"time"
)

// Proof holds the parsed DPoP proof from a request.
type Proof struct {
	JKT       string           // JWK thumbprint (SHA-256 of JWK)
	HTM       string           // HTTP method
	HTU       string           // HTTP URI
	IssuedAt  time.Time        // iat claim
	UniqueID  string           // jti claim
	PublicKey interface{}      // The public key from the proof (crypto.PublicKey)
}
