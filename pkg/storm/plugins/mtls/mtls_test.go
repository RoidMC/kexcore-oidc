package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// --- test helpers ---

func generateTestCert(cn string) (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func generateSignedCert(cn string, root *x509.Certificate, rootKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// --- tests ---

func TestNewWithConfig(t *testing.T) {
	p := NewWithConfig()
	if p.Name() != "mtls" {
		t.Errorf("Name() = %q, want %q", p.Name(), "mtls")
	}
	if p.Category() != storm.CategoryStandard {
		t.Errorf("Category() = %v, want %v", p.Category(), storm.CategoryStandard)
	}
}

func TestRequires(t *testing.T) {
	p := NewWithConfig()
	requires := p.Requires()
	if requires != nil {
		t.Errorf("Requires() = %v, want nil", requires)
	}
}

func TestCertThumbprint(t *testing.T) {
	cert, err := generateTestCert("test-client")
	if err != nil {
		t.Fatal(err)
	}

	tp := CertThumbprint(cert)
	if tp == "" {
		t.Error("CertThumbprint returned empty string")
	}
}

func TestCNFClaim(t *testing.T) {
	cert, err := generateTestCert("test-client")
	if err != nil {
		t.Fatal(err)
	}

	claim := CNFClaim(cert)
	x5t, ok := claim["x5t#S256"].(string)
	if !ok {
		t.Fatal("cnf claim missing x5t#S256")
	}
	if x5t == "" {
		t.Error("x5t#S256 is empty")
	}
}

func TestAuthenticateClient_Success(t *testing.T) {
	cert, err := generateTestCert("test-client")
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/token", nil)
	ctx := ContextWithClientCert(r.Context(), cert)
	r = r.WithContext(ctx)

	ok, err := AuthenticateClient(r, "test-client")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected authentication to succeed")
	}
}

func TestAuthenticateClient_NoCert(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)

	ok, err := AuthenticateClient(r, "test-client")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected authentication to fail without cert")
	}
}

func TestAuthenticateClient_WrongClientID(t *testing.T) {
	cert, err := generateTestCert("test-client")
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/token", nil)
	ctx := ContextWithClientCert(r.Context(), cert)
	r = r.WithContext(ctx)

	ok, err := AuthenticateClient(r, "other-client")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected authentication to fail with wrong client ID")
	}
}

func TestExtractClientIDFromCert_CN(t *testing.T) {
	cert, err := generateTestCert("my-client")
	if err != nil {
		t.Fatal(err)
	}

	id := ExtractClientIDFromCert(cert)
	if id != "my-client" {
		t.Errorf("ExtractClientIDFromCert() = %q, want %q", id, "my-client")
	}
}

func TestValidateCertChain_Valid(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "root-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatal(err)
	}

	childCert, err := generateSignedCert("test-client", rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	err = ValidateCertChain(childCert, roots)
	if err != nil {
		t.Errorf("expected valid chain, got error: %v", err)
	}
}

func TestValidateCertChain_Invalid(t *testing.T) {
	cert, err := generateTestCert("test-client")
	if err != nil {
		t.Fatal(err)
	}

	// Empty roots pool should fail
	roots := x509.NewCertPool()

	err = ValidateCertChain(cert, roots)
	if err == nil {
		t.Error("expected error for invalid chain")
	}
}

func TestClientCertMiddleware_NoCert(t *testing.T) {
	handler := ClientCertMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cert := ClientCertFromContext(r.Context())
		if cert != nil {
			t.Error("expected no cert in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequireClientCertMiddleware_NoCert(t *testing.T) {
	handler := RequireClientCertMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestContextHelpers(t *testing.T) {
	cert, err := generateTestCert("test-client")
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if ClientCertFromContext(ctx) != nil {
		t.Error("expected nil cert from empty context")
	}

	ctx = ContextWithClientCert(ctx, cert)
	got := ClientCertFromContext(ctx)
	if got == nil {
		t.Fatal("expected cert from context")
	}
	if got.Subject.CommonName != "test-client" {
		t.Errorf("cert CN = %q, want %q", got.Subject.CommonName, "test-client")
	}
}

func TestContribute(t *testing.T) {
	p := NewWithConfig()
	cfg := &protocol.DiscoveryConfiguration{}

	ctx := context.Background()
	p.Contribute(ctx, cfg)

	if cfg.TLSClientCertificateBoundAccessTokens != true {
		t.Error("expected TLSClientCertificateBoundAccessTokens to be true")
	}
	if cfg.MTLSEndpointAliases == nil {
		t.Error("expected MTLSEndpointAliases to be set")
	}
}
