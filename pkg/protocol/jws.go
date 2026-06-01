// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package protocol

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/roidmc/kexcore-oidc/pkg/crypto"
)

// JWSSigner is the unified entry point for JWS signing operations.
// Both OP and RP can use it without caring about the underlying implementation
// (software gmsm, HSM, KMS, etc.).
type JWSSigner interface {
	// Sign signs the payload with the key identified by keyID using the specified algorithm.
	// alg is a JWA signature algorithm string, e.g. "RS256", "ES256", "EdDSA", "SGD_SM3_SM2".
	// Returns the compact JWS serialization.
	Sign(ctx context.Context, payload []byte, keyID, alg string) (string, error)
}

// JWSVerifier is the unified entry point for JWS signature verification.
type JWSVerifier interface {
	// Verify verifies the JWS token against the provided KeySet and returns the payload.
	Verify(ctx context.Context, token string, keySet KeySet) ([]byte, error)
}

// JWSService provides both signing and verification capabilities.
// It is the recommended way for upper layers (op, storm, client) to perform JWS operations.
type JWSService interface {
	JWSSigner
	JWSVerifier
}

// VerifySignatureWithRegistry verifies a JWS signature by dispatching to the
// crypto provider registry. If a VerifyProvider is registered for the algorithm,
// it is used. Otherwise, jwx's built-in verification is used as fallback.
//
// This function is the central dispatch point for all JWS signature verification
// in the protocol layer. It replaces the previous hard-coded sm2Verifier in registry.go.
func VerifySignatureWithRegistry(ctx context.Context, jwsMsg *jws.Message, rawToken []byte, key jwk.Key, alg string) ([]byte, error) {
	if provider, ok := crypto.DefaultRegistry.GetVerifier(alg); ok {
		sig := jwsMsg.Signatures()[0]
		sigBytes, err := base64.RawURLEncoding.DecodeString(string(sig.Signature()))
		if err != nil {
			return nil, fmt.Errorf("error decoding signature: %w", err)
		}

		signingInput, err := crypto.BuildSigningInput(sig.ProtectedHeaders(), jwsMsg.Payload())
		if err != nil {
			return nil, err
		}

		raw, err := jwk.Export[any](key)
		if err != nil {
			return nil, fmt.Errorf("error extracting key: %w", err)
		}

		if err := provider.Verify(ctx, signingInput, sigBytes, raw); err != nil {
			return nil, err
		}
		return jwsMsg.Payload(), nil
	}

	sig := jwsMsg.Signatures()[0]
	sigAlg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return nil, fmt.Errorf("missing algorithm in token header")
	}
	return jws.Verify(rawToken, jws.WithKey(sigAlg, key))
}
