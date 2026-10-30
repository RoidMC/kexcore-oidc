package shared

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"

	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
)

// authFakeClient is a minimal Client implementation for ClientAuthHelper tests.
type authFakeClient struct {
	id     string
	method protocol.AuthMethod
}

func (c *authFakeClient) GetID() string                   { return c.id }
func (c *authFakeClient) AuthMethod() protocol.AuthMethod { return c.method }

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
