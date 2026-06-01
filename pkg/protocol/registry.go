package protocol

import (
	"context"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
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
	return VerifySignatureWithRegistry(ctx, jwsMsg, rawToken, key, alg)
}

var defaultRegistry = NewSignatureRegistry()

func init() {
}

func VerifySignature(ctx context.Context, jwsMsg *jws.Message, rawToken []byte, key jwk.Key, alg string) ([]byte, error) {
	if v, ok := defaultRegistry.entries[alg]; ok {
		return v.Verify(jwsMsg, rawToken, key)
	}
	return VerifySignatureWithRegistry(ctx, jwsMsg, rawToken, key, alg)
}
