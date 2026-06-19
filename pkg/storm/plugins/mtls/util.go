package mtls

import (
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

// CertThumbprint computes the SHA-256 thumbprint of a certificate
// as a base64url-encoded string (RFC 8705 §3.1, x5t#S256).
func CertThumbprint(cert *x509.Certificate) string {
	return shared.CertThumbprint(cert)
}

// CNFClaim returns the cnf claim for certificate-bound tokens (RFC 8705 §3.1).
func CNFClaim(cert *x509.Certificate) map[string]any {
	return map[string]any{
		"x5t#S256": CertThumbprint(cert),
	}
}

// AuthenticateClient authenticates the client using the TLS client
// certificate per RFC 8705 Section 3.
// It checks that a certificate was presented and extracts the client ID.
// Certificate chain validation is the responsibility of the TLS layer
// (for tls_client_auth) or should be done separately via ValidateCertChain
// (for self_signed_tls_client_auth).
func AuthenticateClient(r *http.Request, clientID string) (bool, error) {
	cert := ClientCertFromContext(r.Context())
	if cert == nil {
		return false, nil
	}

	// For tls_client_auth: the TLS layer already validated the chain.
	// For self_signed_tls_client_auth: the caller should use ValidateCertChain.
	// Here we just verify the certificate has the expected client ID.
	extractedID := ExtractClientIDFromCert(cert)
	if extractedID == "" {
		return false, nil
	}
	if extractedID != clientID {
		return false, nil
	}

	return true, nil
}

// ExtractClientIDFromCert extracts the client ID from a certificate.
// Checks the CommonName first, then the SAN URI.
func ExtractClientIDFromCert(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	for _, uri := range cert.URIs {
		if uri.Scheme == "oidc" && uri.Host == "client" {
			return uri.Path
		}
	}
	return ""
}

// ValidateCertChain verifies the certificate chain against trusted roots.
func ValidateCertChain(cert *x509.Certificate, roots *x509.CertPool) error {
	if roots == nil {
		roots = x509.NewCertPool()
		roots.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}
	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}
	return nil
}
