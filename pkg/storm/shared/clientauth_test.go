package shared

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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
)

// authFakeClient is a minimal Client implementation for ClientAuthHelper tests.
type authFakeClient struct {
	id     string
	method protocol.AuthMethod
	jwks   []jwk.Key
}

func (c *authFakeClient) GetID() string                   { return c.id }
func (c *authFakeClient) AuthMethod() protocol.AuthMethod { return c.method }
func (c *authFakeClient) ClientJWKS() []jwk.Key           { return c.jwks }

type authFakeStore struct {
	client *authFakeClient
}

func (s *authFakeStore) GetClientByClientID(_ context.Context, clientID string) (Client, error) {
	if s.client != nil && s.client.id == clientID {
		return s.client, nil
	}
	return nil, protocol.ErrInvalidClient()
}

func (s *authFakeStore) AuthorizeClientIDSecret(_ context.Context, clientID, clientSecret string) error {
	if s.client != nil && s.client.id == clientID && clientSecret == "secret" {
		return nil
	}
	return protocol.ErrInvalidClient()
}

func authRequest(form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// RFC 7523 §2.2 / FAPI 2.0: a client registered for private_key_jwt that omits
// the client_assertion must be rejected instead of silently falling back to
// client_id + client_secret authentication. This protects every endpoint that
// shares ClientAuthHelper (introspection, revocation, device).
func TestClientAuthHelper_PrivateKeyJWTRequiresAssertion(t *testing.T) {
	h := NewClientAuthHelper(&authFakeStore{client: &authFakeClient{
		id:     "fapi-client",
		method: protocol.AuthMethodPrivateKeyJWT,
	}})

	_, err := h.AuthenticateClient(authRequest(url.Values{"client_id": {"fapi-client"}}))

	require.Error(t, err)
	assert.ErrorIs(t, err, protocol.ErrInvalidClient())
	assert.Contains(t, err.Error(), "client_assertion required")
}

// client_secret clients must keep working after the private_key_jwt guard.
func TestClientAuthHelper_ClientSecret(t *testing.T) {
	h := NewClientAuthHelper(&authFakeStore{client: &authFakeClient{
		id:     "web-client",
		method: protocol.AuthMethodPost,
	}})

	client, err := h.AuthenticateClient(authRequest(url.Values{
		"client_id":     {"web-client"},
		"client_secret": {"secret"},
	}))

	require.NoError(t, err)
	assert.Equal(t, "web-client", client.GetID())
}

// RFC 8705 §2: tls_client_auth clients require a client certificate.
func TestClientAuthHelper_TLSClientAuthRequiresCertificate(t *testing.T) {
	h := NewClientAuthHelper(&authFakeStore{client: &authFakeClient{
		id:     "mtls-client",
		method: protocol.AuthMethodTLSClientAuth,
	}})

	_, err := h.AuthenticateClient(authRequest(url.Values{"client_id": {"mtls-client"}}))

	require.Error(t, err)
	assert.ErrorIs(t, err, protocol.ErrInvalidClient())
	assert.Contains(t, err.Error(), "mTLS client certificate is required")
}

// ---------------------------------------------------------------------------
// RFC 8705 §2.2 — self_signed_tls_client_auth
// ---------------------------------------------------------------------------

// genSelfSignedCert generates a self-signed certificate (RFC 8705 §2.2).
func genSelfSignedCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mtls-client"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// genCASignedCert returns a leaf certificate signed by a separate CA key —
// i.e. NOT self-signed.
func genCASignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mtls-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return leaf
}

func selfSignedAuthRequest(t *testing.T, jwks []jwk.Key) *ClientAuthHelper {
	t.Helper()
	return NewClientAuthHelper(&authFakeStore{client: &authFakeClient{
		id:     "mtls-ss-client",
		method: protocol.AuthMethodSelfSignedTLSAuth,
		jwks:   jwks,
	}})
}

func selfSignedAuthReq(t *testing.T, h *ClientAuthHelper, cert *x509.Certificate) (Client, error) {
	t.Helper()
	req := authRequest(url.Values{"client_id": {"mtls-ss-client"}})
	if cert != nil {
		req = req.WithContext(ContextWithClientCert(req.Context(), cert))
	}
	return h.AuthenticateClient(req)
}

// RFC 8705 §2.2: self-signed certificate whose public key is registered in the
// client jwks authenticates the client.
func TestClientAuthHelper_SelfSignedTLSClientAuth(t *testing.T) {
	key, cert := genSelfSignedCert(t)
	jk, err := jwk.Import[jwk.Key](&key.PublicKey)
	require.NoError(t, err)

	client, err := selfSignedAuthReq(t, selfSignedAuthRequest(t, []jwk.Key{jk}), cert)

	require.NoError(t, err)
	assert.Equal(t, "mtls-ss-client", client.GetID())
}

// The presented key must match a registered jwks key.
func TestClientAuthHelper_SelfSignedTLSKeyMismatch(t *testing.T) {
	_, cert := genSelfSignedCert(t)
	otherKey, _ := genSelfSignedCert(t)
	jk, err := jwk.Import[jwk.Key](&otherKey.PublicKey)
	require.NoError(t, err)

	_, err = selfSignedAuthReq(t, selfSignedAuthRequest(t, []jwk.Key{jk}), cert)

	require.Error(t, err)
	assert.ErrorIs(t, err, protocol.ErrInvalidClient())
	assert.Contains(t, err.Error(), "does not match any registered jwks key")
}

// A CA-signed certificate must be rejected even when its public key is
// registered — the certificate itself must be self-signed (RFC 8705 §2.2).
func TestClientAuthHelper_SelfSignedTLSRejectsCASignedCert(t *testing.T) {
	caSigned := genCASignedCert(t)
	jk, err := jwk.Import[jwk.Key](caSigned.PublicKey)
	require.NoError(t, err)

	_, err = selfSignedAuthReq(t, selfSignedAuthRequest(t, []jwk.Key{jk}), caSigned)

	require.Error(t, err)
	assert.ErrorIs(t, err, protocol.ErrInvalidClient())
	assert.Contains(t, err.Error(), "not self-signed")
}

// Missing client certificate and missing registered keys must both fail.
func TestClientAuthHelper_SelfSignedTLSNegative(t *testing.T) {
	_, cert := genSelfSignedCert(t)

	// No certificate presented.
	_, err := selfSignedAuthReq(t, selfSignedAuthRequest(t, nil), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mTLS client certificate is required")

	// Certificate presented but no jwks registered.
	_, err = selfSignedAuthReq(t, selfSignedAuthRequest(t, nil), cert)
	require.Error(t, err)
	assert.ErrorIs(t, err, protocol.ErrInvalidClient())
	assert.Contains(t, err.Error(), "no registered jwks keys")
}
