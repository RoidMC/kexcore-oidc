// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package shared

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"go.opentelemetry.io/otel/trace"
)

// --- DPoP context ---

// DPoPProof is the minimal interface for a DPoP proof stored in context.
// Defined here to avoid import cycles between plugins.
type DPoPProof interface {
	JWKThumbprint() string
	AccessTokenHash() string // ath claim (base64url(SHA-256(access_token))), empty if absent
}

type dpopContextKey struct{}

// ContextWithDPoP stores a DPoP proof in the request context.
func ContextWithDPoP(ctx context.Context, proof DPoPProof) context.Context {
	return context.WithValue(ctx, dpopContextKey{}, proof)
}

// DPoPFromContext retrieves the DPoP proof from the context.
// Returns nil if no DPoP proof was presented.
func DPoPFromContext(ctx context.Context) DPoPProof {
	p, _ := ctx.Value(dpopContextKey{}).(DPoPProof)
	return p
}

// --- mTLS client certificate context ---

type clientCertContextKey struct{}

// ContextWithClientCert stores the TLS client certificate in the request context.
func ContextWithClientCert(ctx context.Context, cert *x509.Certificate) context.Context {
	return context.WithValue(ctx, clientCertContextKey{}, cert)
}

// ClientCertFromContext retrieves the TLS client certificate from the context.
// Returns nil if no certificate was presented.
func ClientCertFromContext(ctx context.Context) *x509.Certificate {
	cert, _ := ctx.Value(clientCertContextKey{}).(*x509.Certificate)
	return cert
}

// CertThumbprint computes the SHA-256 thumbprint of a certificate
// as a base64url-encoded string (RFC 8705 §3.1, x5t#S256).
func CertThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// --- Pre-authenticated client context (for private_key_jwt / client_secret_jwt) ---

// AuthenticatedClient is the minimal interface for a client that has already
// been authenticated by an assertion-based method (RFC 7523 §2.2, OIDC Core §9).
type AuthenticatedClient interface {
	GetID() string
}

type authenticatedClientKey struct{}

// ContextWithAuthenticatedClient stores a pre-authenticated client in the context.
func ContextWithAuthenticatedClient(ctx context.Context, client AuthenticatedClient) context.Context {
	return context.WithValue(ctx, authenticatedClientKey{}, client)
}

// AuthenticatedClientFromContext retrieves a pre-authenticated client from the context.
// Returns nil if no client was pre-authenticated.
func AuthenticatedClientFromContext(ctx context.Context) AuthenticatedClient {
	c, _ := ctx.Value(authenticatedClientKey{}).(AuthenticatedClient)
	return c
}

// VerifyTokenBinding verifies that the current request proves possession
// of the key bound to the token via cnf claim (RFC 8705 §5, RFC 9449 §7.2).
//
// This is a stateless function that checks:
//   - cnf.jkt against DPoP proof in context
//   - cnf.x5t#S256 against TLS client certificate in context
//
// Returns nil if the token is not sender-constrained (no cnf) or if
// verification succeeds. Returns a protocol error otherwise.
func VerifyTokenBinding(ctx context.Context, cnf map[string]any) error {
	if len(cnf) == 0 {
		return nil
	}

	hasDPoPBinding := false
	hasMtlsBinding := false

	// Check if cnf has DPoP and/or mTLS binding claims
	jkt, hasJKT := cnf["jkt"].(string)
	x5t, hasX5T := cnf["x5t#S256"].(string)
	if hasJKT && jkt != "" {
		hasDPoPBinding = true
	}
	if hasX5T && x5t != "" {
		hasMtlsBinding = true
	}

	// When both DPoP and mTLS bindings are present (holder-of-key mode),
	// either proof of possession suffices — the variant determines which
	// mechanism the client actually uses.
	if hasDPoPBinding && hasMtlsBinding {
		dpopOK := false
		mtlsOK := false

		if proof := DPoPFromContext(ctx); proof != nil {
			if proof.JWKThumbprint() == jkt {
				dpopOK = true
			}
		}
		if cert := ClientCertFromContext(ctx); cert != nil {
			if CertThumbprint(cert) == x5t {
				mtlsOK = true
			}
		}
		if !dpopOK && !mtlsOK {
			return protocol.ErrInvalidRequest().WithDescription("holder-of-key proof required (DPoP jkt or mTLS certificate)")
		}
		return nil
	}

	// DPoP binding only: cnf.jkt must match the DPoP proof's jkt
	if hasDPoPBinding {
		proof := DPoPFromContext(ctx)
		if proof == nil {
			return protocol.ErrInvalidRequest().WithDescription("DPoP proof required for this token")
		}
		if proof.JWKThumbprint() != jkt {
			return protocol.ErrInvalidRequest().WithDescription("DPoP proof jkt does not match token binding")
		}
	}

	// mTLS binding only: cnf.x5t#S256 must match the client certificate fingerprint
	if hasMtlsBinding {
		cert := ClientCertFromContext(ctx)
		if cert == nil {
			return protocol.ErrInvalidRequest().WithDescription("client certificate required for this token")
		}
		if CertThumbprint(cert) != x5t {
			return protocol.ErrInvalidRequest().WithDescription("client certificate does not match token binding")
		}
	}

	return nil
}

// ResolveCNF builds the cnf (confirmation) claim from mTLS and DPoP context.
// mTLS: cnf.x5t#S256 (RFC 8705 §3.1)
// DPoP: cnf.jkt (RFC 9449 §7.1)
// If both are present, both keys are included.
// Returns nil if neither mTLS nor DPoP context is present.
func ResolveCNF(ctx context.Context) map[string]any {
	var cnf map[string]any

	if cert := ClientCertFromContext(ctx); cert != nil {
		if cnf == nil {
			cnf = make(map[string]any)
		}
		cnf["x5t#S256"] = CertThumbprint(cert)
	}

	if proof := DPoPFromContext(ctx); proof != nil {
		if cnf == nil {
			cnf = make(map[string]any)
		}
		cnf["jkt"] = proof.JWKThumbprint()
	}

	return cnf
}

// ValidateDPoPProofATH validates the ath (access token hash) claim in a DPoP
// proof against the actual access token (RFC 9449 §7.1).
// The ath claim MUST equal base64url(SHA-256(access_token)).
func ValidateDPoPProofATH(proof DPoPProof, accessToken string) error {
	ath := proof.AccessTokenHash()
	if ath == "" {
		return protocol.ErrInvalidRequest().WithDescription("DPoP proof missing ath claim")
	}
	hash := sha256.Sum256([]byte(accessToken))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	if ath != expected {
		return protocol.ErrInvalidRequest().WithDescription("DPoP proof ath does not match access token")
	}
	return nil
}

// --- OpenTelemetry helpers ---

// TracerSpan starts a span from a trace.Tracer. If the tracer is nil,
// it returns a no-op span from the context. This is the recommended
// way to start spans in plugins to avoid nil-pointer panics in tests.
func TracerSpan(ctx context.Context, tracer trace.Tracer, name string) (context.Context, trace.Span) {
	if tracer != nil {
		return tracer.Start(ctx, name)
	}
	return ctx, trace.SpanFromContext(ctx)
}

// --- JARM signing algorithm preference ---

type jarmPreferredAlgContextKey struct{}

// ContextWithJARMPreferredAlg stores the client's preferred signing algorithm
// in the context so the JARM plugin can use it for signing.
func ContextWithJARMPreferredAlg(ctx context.Context, alg string) context.Context {
	return context.WithValue(ctx, jarmPreferredAlgContextKey{}, alg)
}

// JARMPreferredAlgFromContext retrieves the client's preferred signing algorithm.
func JARMPreferredAlgFromContext(ctx context.Context) string {
	s, _ := ctx.Value(jarmPreferredAlgContextKey{}).(string)
	return s
}
