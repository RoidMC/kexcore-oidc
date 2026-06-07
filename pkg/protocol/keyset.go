package protocol

import (
	"context"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// KeyStore provides access to a set of JSON Web Keys and the signature algorithms they support.
type KeyStore interface {
	KeySet(ctx context.Context) ([]Key, error)
	SignatureAlgorithms(ctx context.Context) ([]string, error)
}

// Key represents a single JSON Web Key with metadata.
type Key interface {
	ID() string
	Algorithm() string
	Use() string
	Key() jwk.Key
}

// CertificateProvider is an optional extension of Key for X.509 certificate chain support.
// OP implementations can satisfy this interface to include x5c/x5t/x5u fields in JWKS.
//
// Usage in JWKS endpoint:
//
//	if cp, ok := key.(protocol.CertificateProvider); ok {
//	    certs, err := cp.CertificateChain()
//	    if err == nil && len(certs) > 0 {
//	        jwkKey.Set(jwk.X509CertChainKey, certs)
//	    }
//	}
type CertificateProvider interface {
	// CertificateChain returns the DER-encoded X.509 certificate chain for this key.
	// The first element is the end-entity certificate.
	// Returns nil if no certificate is associated with this key.
	CertificateChain() ([][]byte, error)
}

// GMJWKProvider is an optional extension of Key for GM/T (国密) keys.
// OP implementations can satisfy this interface to provide custom JWKS
// serialization for SM2/SM9 keys that jwx cannot represent as jwk.Key.
// RP/RS clients never need this — they consume standard JWKS JSON.
//
// JWKS endpoints discover GM/T capability via type assertion:
//
//	if gm, ok := key.(protocol.GMJWKProvider); ok && gm.GMJWK() != nil {
//	    // use GMJWK for serialization
//	}
type GMJWKProvider interface {
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

// SigningKey represents a key used for signing operations.
type SigningKey interface {
	ID() string
	Algorithm() string
	Key() jwk.Key
}

// KeyUseSignature is the JWK "use" value that indicates a key is intended for digital signatures.
const KeyUseSignature = "sig"

// KeySet represents a set of JSON Web Keys
//   - remotely fetch via discovery and jwks_uri -> `remoteKeySet`
//   - held by the OP itself in storage -> `openIDKeySet`
//   - dynamically aggregated by request for OAuth JWT Profile Assertion -> `jwtProfileKeySet`
type KeySet interface {
	// VerifySignature verifies the signature with the given keyset and returns the raw payload
	VerifySignature(ctx context.Context, rawToken []byte) (payload []byte, err error)
}

// GetKeyIDAndAlg returns the `kid` and `alg` claim from the JWS header.
func GetKeyIDAndAlg(jwsMsg *jws.Message) (string, string) {
	keyID := ""
	alg := ""
	for _, sig := range jwsMsg.Signatures() {
		keyID, _ = sig.ProtectedHeaders().KeyID()
		sigAlg, _ := sig.ProtectedHeaders().Algorithm()
		alg = sigAlg.String()
		break
	}
	return keyID, alg
}

// FindMatchingKey searches the given JSON Web Keys for the requested key ID, usage and alg type.
//
// It returns the key immediately on an exact (id, usage, type) match.
//
// It returns a specific error if none (ErrKeyNone) or multiple (ErrKeyMultiple) match.
func FindMatchingKey(keyID, use, expectedAlg string, keys ...jwk.Key) (key jwk.Key, err error) {
	var validKeys []jwk.Key
	for _, k := range keys {
		keyUsage, _ := k.KeyUsage()
		if keyUsage != use && keyUsage != "" {
			continue
		}
		if !algToKeyType(k, expectedAlg) {
			continue
		}
		kid, _ := k.KeyID()
		if kid == keyID && keyID != "" {
			return k, nil
		}
		if kid == "" || keyID == "" {
			validKeys = append(validKeys, k)
		}
	}
	if len(validKeys) == 1 {
		return validKeys[0], nil
	}
	if len(validKeys) > 1 {
		return nil, ErrKeyMultiple
	}
	return nil, ErrKeyNone
}

func algToKeyType(key jwk.Key, alg string) bool {
	kty := key.KeyType()
	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
		return kty == jwa.RSA()
	}
	if strings.HasPrefix(alg, "ES") || alg == "SGD_SM3_SM2" {
		return kty == jwa.EC()
	}
	if alg == "EdDSA" {
		return kty == jwa.OKP()
	}
	return false
}
