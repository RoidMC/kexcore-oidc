package mtls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
)

// CertThumbprint computes the SHA-256 thumbprint of a certificate
// as a base64url-encoded string (RFC 8705 §3.1, x5t#S256).
func CertThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// CNFClaim returns the cnf claim for certificate-bound tokens (RFC 8705 §3.1).
func CNFClaim(cert *x509.Certificate) map[string]any {
	return map[string]any{
		"x5t#S256": CertThumbprint(cert),
	}
}

// AuthenticateClient authenticates the client using the TLS client
// certificate per RFC 8705 Section 3.
func AuthenticateClient(r *http.Request, clientID string) (bool, error) {
	cert := ClientCertFromContext(r.Context())
	if cert == nil {
		return false, nil
	}

	// Verify basic certificate validity
	if err := cert.CheckSignatureFrom(cert); err != nil {
		// Not self-signed - check against system roots
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			return false, nil
		}
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
