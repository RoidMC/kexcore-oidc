// Package revocation — tests for RFC 7009 Token Revocation.
package revocation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	crypto_pkg "github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

var errNotFound = errors.New("not found")

// --- fakes ---

type fakeRevocationStore struct {
	revokeFn func(ctx context.Context, tokenID, subject, clientID string) *protocol.Error
	rtInfoFn func(ctx context.Context, clientID, refreshToken string) (string, string, error)
}

func (s *fakeRevocationStore) RevokeToken(ctx context.Context, tokenID, subject, clientID string) *protocol.Error {
	if s.revokeFn != nil {
		return s.revokeFn(ctx, tokenID, subject, clientID)
	}
	return nil
}
func (s *fakeRevocationStore) GetRefreshTokenInfo(ctx context.Context, clientID, refreshToken string) (string, string, error) {
	if s.rtInfoFn != nil {
		return s.rtInfoFn(ctx, clientID, refreshToken)
	}
	return "", "", ErrInvalidRefreshToken
}

var _ storm.RevocationStore = (*fakeRevocationStore)(nil)

type fakeClient struct {
	id     string
	secret string
}

func (c *fakeClient) GetID() string                   { return c.id }
func (c *fakeClient) AuthMethod() protocol.AuthMethod { return protocol.AuthMethodBasic }
func (c *fakeClient) LoginURL(string) string          { return "" }

var _ storm.Client = (*fakeClient)(nil)

type fakeCrypto struct {
	decryptFn func(ctx context.Context, ciphertext []byte) ([]byte, error)
}

func (c *fakeCrypto) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}
func (c *fakeCrypto) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if c.decryptFn != nil {
		return c.decryptFn(ctx, ciphertext)
	}
	return nil, errNotFound
}
func (c *fakeCrypto) Hash(_ context.Context, sigAlgorithm string, data []byte) ([]byte, error) {
	h, _ := crypto_pkg.GetHashAlgorithm(sigAlgorithm)
	h.Write(data)
	return h.Sum(nil), nil
}
func (c *fakeCrypto) Sign(_ context.Context, _ string, _ []byte) (string, error) { return "", nil }
func (c *fakeCrypto) AlgorithmSuite() string                                     { return "RSA+SHA256+AES" }

var _ storm.UniCrypto = (*fakeCrypto)(nil)

type fakeKeyStore struct{}

func (s *fakeKeyStore) KeySet(_ context.Context) ([]protocol.Key, error) { return nil, nil }
func (s *fakeKeyStore) SignatureAlgorithms(_ context.Context) ([]string, error) {
	return []string{"RS256"}, nil
}
func (s *fakeKeyStore) SigningKey(_ context.Context) (storm.SigningKey, error) { return nil, nil }

// --- helpers ---

const testIssuer = "https://op.example.com"

func newClientAuthHelper(client *fakeClient) *shared.ClientAuthHelper {
	return shared.NewClientAuthHelperFromFuncs(
		func(ctx context.Context, clientID string) (shared.Client, error) {
			if client != nil && client.id == clientID {
				return client, nil
			}
			return nil, errNotFound
		},
		func(ctx context.Context, clientID, clientSecret string) error {
			if client != nil && client.id == clientID && client.secret == clientSecret {
				return nil
			}
			return errNotFound
		},
	)
}

func newTestPlugin(store storm.RevocationStore, client *fakeClient, crypto storm.UniCrypto) *Plugin {
	return &Plugin{
		store:      store,
		clientAuth: newClientAuthHelper(client),
		crypto:     crypto,
		keyStore:   &fakeKeyStore{},
	}
}

func newFormRequest(method, target string, form url.Values) *http.Request {
	var r *http.Request
	if method == http.MethodPost {
		r = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	ctx := shared.ContextWithIssuer(r.Context(), testIssuer)
	return r.WithContext(ctx)
}

func newBasicAuthRequest(method, target, clientID, clientSecret string, form url.Values) *http.Request {
	r := newFormRequest(method, target, form)
	r.SetBasicAuth(clientID, clientSecret)
	return r
}

func serveRequest(plugin *Plugin, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	plugin.handle(w, r)
	return w
}

// --- Tests ---

// RFC 7009 §2: Revoke access token → 200.
func TestRevocation_RevokeAccessToken(t *testing.T) {
	var revokedToken string
	store := &fakeRevocationStore{
		revokeFn: func(ctx context.Context, tokenID, subject, clientID string) *protocol.Error {
			revokedToken = tokenID
			return nil
		},
	}
	client := &fakeClient{id: "myclient", secret: "secret"}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("token123:user001"), nil
		},
	}
	p := newTestPlugin(store, client, crypto)

	form := url.Values{"token": {"opaque-token"}}
	r := newBasicAuthRequest(http.MethodPost, "/revoke", "myclient", "secret", form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "token123", revokedToken)
}

// RFC 7009 §2: Revoke refresh token → 200.
func TestRevocation_RevokeRefreshToken(t *testing.T) {
	var revokedToken string
	store := &fakeRevocationStore{
		revokeFn: func(ctx context.Context, tokenID, subject, clientID string) *protocol.Error {
			revokedToken = tokenID
			return nil
		},
		rtInfoFn: func(ctx context.Context, clientID, refreshToken string) (string, string, error) {
			return "user001", "rt-token-id", nil
		},
	}
	client := &fakeClient{id: "myclient", secret: "secret"}
	p := newTestPlugin(store, client, &fakeCrypto{})

	form := url.Values{"token": {"refresh-token-string"}, "token_type_hint": {"refresh_token"}}
	r := newBasicAuthRequest(http.MethodPost, "/revoke", "myclient", "secret", form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "rt-token-id", revokedToken)
}

// RFC 7009 §2.2: Invalid token → 200 (not 400).
func TestRevocation_InvalidToken_Still200(t *testing.T) {
	store := &fakeRevocationStore{
		revokeFn: func(ctx context.Context, tokenID, subject, clientID string) *protocol.Error {
			return nil // storage accepts it silently
		},
	}
	client := &fakeClient{id: "myclient", secret: "secret"}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return nil, errNotFound
		},
	}
	p := newTestPlugin(store, client, crypto)

	form := url.Values{"token": {"unknown-token"}}
	r := newBasicAuthRequest(http.MethodPost, "/revoke", "myclient", "secret", form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusOK, w.Code)
}

// Missing token → error.
func TestRevocation_MissingToken_Error(t *testing.T) {
	store := &fakeRevocationStore{}
	client := &fakeClient{id: "myclient", secret: "secret"}
	p := newTestPlugin(store, client, &fakeCrypto{})

	form := url.Values{}
	r := newBasicAuthRequest(http.MethodPost, "/revoke", "myclient", "secret", form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// Unknown client → error.
func TestRevocation_UnknownClient_Error(t *testing.T) {
	store := &fakeRevocationStore{}
	client := &fakeClient{id: "myclient", secret: "secret"}
	p := newTestPlugin(store, client, &fakeCrypto{})

	form := url.Values{"token": {"some-token"}, "client_id": {"unknown"}, "client_secret": {"wrong"}}
	r := newFormRequest(http.MethodPost, "/revoke", form)
	w := serveRequest(p, r)

	// WriteError maps ErrInvalidClient to 401 per RFC 6749 §5.2
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// Chi router: POST /revoke route registered.
func TestRevocation_ChiRouter(t *testing.T) {
	store := &fakeRevocationStore{
		revokeFn: func(ctx context.Context, tokenID, subject, clientID string) *protocol.Error {
			return nil
		},
	}
	client := &fakeClient{id: "test", secret: "test"}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("t:s"), nil
		},
	}
	p := newTestPlugin(store, client, crypto)

	r := chi.NewRouter()
	p.Register(r)

	form := url.Values{"token": {"tok"}}
	req := newBasicAuthRequest(http.MethodPost, "/revoke", "test", "test", form)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

// Discovery: contributes revocation_endpoint and auth methods.
func TestRevocation_Contribute(t *testing.T) {
	p := &Plugin{}
	ctx := shared.ContextWithIssuer(context.Background(), "https://op.example.com")
	cfg := &protocol.DiscoveryConfiguration{}
	p.Contribute(ctx, cfg)

	assert.Equal(t, "https://op.example.com/revoke", cfg.RevocationEndpoint)
	assert.Contains(t, cfg.RevocationEndpointAuthMethodsSupported, "client_secret_basic")
}

// Plugin lifecycle: Name, Category, Requires.
func TestRevocation_PluginLifecycle(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "revocation", p.Name())
	assert.Equal(t, storm.CategoryStandard, p.Category())
	assert.Contains(t, p.Requires(), "RevocationStore")
	assert.Contains(t, p.Requires(), "ClientStore")
}
