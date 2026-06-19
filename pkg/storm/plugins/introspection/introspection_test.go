// Package introspection — tests for RFC 7662 Token Introspection.
package introspection

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	crypto_pkg "github.com/roidmc/kexcore-oidc/v2/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

var errNotFound = errors.New("not found")

// --- fakes ---

type fakeIntrospectStore struct {
	setFn func(ctx context.Context, resp *protocol.IntrospectionResponse, tokenID, subject, clientID string) error
}

func (s *fakeIntrospectStore) SetIntrospectionFromToken(ctx context.Context, resp *protocol.IntrospectionResponse, tokenID, subject, clientID string) error {
	if s.setFn != nil {
		return s.setFn(ctx, resp, tokenID, subject, clientID)
	}
	return nil
}

var _ storm.IntrospectStore = (*fakeIntrospectStore)(nil)

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

func newTestPlugin(store storm.IntrospectStore, client *fakeClient, crypto storm.UniCrypto) *Plugin {
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

// RFC 7662 §2.2: Active token returns active=true with claims.
func TestIntrospection_ActiveToken(t *testing.T) {
	store := &fakeIntrospectStore{
		setFn: func(ctx context.Context, resp *protocol.IntrospectionResponse, tokenID, subject, clientID string) error {
			resp.Active = true
			resp.Subject = subject
			resp.ClientID = clientID
			resp.Scope = protocol.SpaceDelimitedArray{"openid", "profile"}
			resp.TokenType = "Bearer"
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
	r := newBasicAuthRequest(http.MethodPost, "/introspect", "myclient", "secret", form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusOK, w.Code)
	var resp protocol.IntrospectionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Active)
	assert.Equal(t, "user001", resp.Subject)
	assert.Equal(t, "myclient", resp.ClientID)
	assert.Equal(t, protocol.SpaceDelimitedArray{"openid", "profile"}, resp.Scope)
}

// RFC 7662 §2.2: Invalid token returns active=false (no error).
func TestIntrospection_InactiveToken(t *testing.T) {
	store := &fakeIntrospectStore{}
	client := &fakeClient{id: "myclient", secret: "secret"}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return nil, errNotFound
		},
	}
	p := newTestPlugin(store, client, crypto)

	form := url.Values{"token": {"bad-token"}}
	r := newBasicAuthRequest(http.MethodPost, "/introspect", "myclient", "secret", form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusOK, w.Code)
	var resp protocol.IntrospectionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Active)
}

// RFC 7662 §2.2: Store error returns active=false.
func TestIntrospection_StoreError_ReturnsInactive(t *testing.T) {
	store := &fakeIntrospectStore{
		setFn: func(ctx context.Context, resp *protocol.IntrospectionResponse, tokenID, subject, clientID string) error {
			return errors.New("db error")
		},
	}
	client := &fakeClient{id: "myclient", secret: "secret"}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("token123:user001"), nil
		},
	}
	p := newTestPlugin(store, client, crypto)

	form := url.Values{"token": {"good-token"}}
	r := newBasicAuthRequest(http.MethodPost, "/introspect", "myclient", "secret", form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusOK, w.Code)
	var resp protocol.IntrospectionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Active)
}

// RFC 7662 §2.1: Missing token parameter returns error.
func TestIntrospection_MissingToken_Error(t *testing.T) {
	store := &fakeIntrospectStore{}
	client := &fakeClient{id: "myclient", secret: "secret"}
	p := newTestPlugin(store, client, &fakeCrypto{})

	form := url.Values{}
	r := newBasicAuthRequest(http.MethodPost, "/introspect", "myclient", "secret", form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// RFC 7662 §2.1: Unknown client returns error.
func TestIntrospection_UnknownClient_Error(t *testing.T) {
	store := &fakeIntrospectStore{}
	client := &fakeClient{id: "myclient", secret: "secret"}
	p := newTestPlugin(store, client, &fakeCrypto{})

	form := url.Values{"token": {"some-token"}, "client_id": {"unknown"}, "client_secret": {"wrong"}}
	r := newFormRequest(http.MethodPost, "/introspect", form)
	w := serveRequest(p, r)

	// WriteError maps ErrInvalidClient to 401 per RFC 6749 §5.2
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// Chi router integration: POST /introspect route registered.
func TestIntrospection_ChiRouter(t *testing.T) {
	store := &fakeIntrospectStore{
		setFn: func(ctx context.Context, resp *protocol.IntrospectionResponse, tokenID, subject, clientID string) error {
			resp.Active = true
			resp.Subject = subject
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
	req := newBasicAuthRequest(http.MethodPost, "/introspect", "test", "test", form)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

// Discovery: contributes introspection_endpoint and auth methods.
func TestIntrospection_Contribute(t *testing.T) {
	p := &Plugin{}
	ctx := shared.ContextWithIssuer(context.Background(), "https://op.example.com")
	cfg := &protocol.DiscoveryConfiguration{}
	p.Contribute(ctx, cfg)

	assert.Equal(t, "https://op.example.com/introspect", cfg.IntrospectionEndpoint)
	assert.Contains(t, cfg.IntrospectionEndpointAuthMethodsSupported, "client_secret_basic")
}

// Plugin lifecycle: Name, Category, Requires.
func TestIntrospection_PluginLifecycle(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "introspection", p.Name())
	assert.Equal(t, storm.CategoryStandard, p.Category())
	assert.Contains(t, p.Requires(), "IntrospectStore")
	assert.Contains(t, p.Requires(), "ClientStore")
}
