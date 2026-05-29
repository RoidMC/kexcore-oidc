package protocol

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
)

type SignatureVerifier interface {
	Algorithm() string
	Verify(jwsMsg *jws.Message, rawToken []byte, key jwk.Key) ([]byte, error)
}

type SignatureRegistry struct {
	entries map[string]SignatureVerifier
}

func NewSignatureRegistry() *SignatureRegistry {
	return &SignatureRegistry{
		entries: make(map[string]SignatureVerifier),
	}
}

func (r *SignatureRegistry) Register(v SignatureVerifier) {
	r.entries[v.Algorithm()] = v
}

func (r *SignatureRegistry) Verify(ctx context.Context, jwsMsg *jws.Message, rawToken []byte, key jwk.Key, alg string) ([]byte, error) {
	if v, ok := r.entries[alg]; ok {
		return v.Verify(jwsMsg, rawToken, key)
	}
	sig := jwsMsg.Signatures()[0]
	sigAlg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return nil, fmt.Errorf("missing algorithm in token header")
	}
	return jws.Verify(rawToken, jws.WithKey(sigAlg, key))
}

type sm2Verifier struct{}

func (sm2Verifier) Algorithm() string { return crypto.SGD_SM3_SM2 }

func (sm2Verifier) Verify(jwsMsg *jws.Message, _ []byte, key jwk.Key) ([]byte, error) {
	sig := jwsMsg.Signatures()[0]
	sigBytes, err := base64.RawURLEncoding.DecodeString(string(sig.Signature()))
	if err != nil {
		return nil, fmt.Errorf("error decoding SM2 signature: %w", err)
	}

	signingInput, err := crypto.BuildSigningInput(sig.ProtectedHeaders(), jwsMsg.Payload())
	if err != nil {
		return nil, err
	}

	raw, err := jwk.Export[any](key)
	if err != nil {
		return nil, fmt.Errorf("error extracting public key: %w", err)
	}
	pubKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PublicKey, got %T", raw)
	}

	if err := crypto.VerifySM2JWSSignature(signingInput, sigBytes, pubKey); err != nil {
		return nil, err
	}
	return jwsMsg.Payload(), nil
}

var defaultRegistry = NewSignatureRegistry()

func init() {
	defaultRegistry.Register(sm2Verifier{})
}

func VerifySignature(ctx context.Context, jwsMsg *jws.Message, rawToken []byte, key jwk.Key, alg string) ([]byte, error) {
	return defaultRegistry.Verify(ctx, jwsMsg, rawToken, key, alg)
}
