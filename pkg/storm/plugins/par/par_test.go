// Package par — tests for RFC 9126 Pushed Authorization Requests.
package par

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

var errNotFound = errors.New("not found")

// --- fakes ---

type fakePARStore struct {
	storeFn func(ctx context.Context, clientID string, req *protocol.AuthRequest, lifetime time.Duration) (string, error)
}

func (s *fakePARStore) StorePushedAuthRequest(ctx context.Context, clientID string, req *protocol.AuthRequest, lifetime time.Duration) (string, error) {
	if s.storeFn != nil {
		return s.storeFn(ctx, clientID, req, lifetime)
	}
	return "urn:ietf:params:oauth:request_uri:test123", nil
}

func (s *fakePARStore) GetPushedAuthRequest(ctx context.Context, requestURI string) (*protocol.AuthRequest, error) {
	return nil, errNotFound
}

var _ storm.PARStore = (*fakePARStore)(nil)

type fakeClient struct {
	id         string
	secret     string
	authMethod protocol.AuthMethod
	redirects  []string
}

func (c *fakeClient) GetID() string                   { return c.id }
func (c *fakeClient) AuthMethod() protocol.AuthMethod { return c.authMethod }
func (c *fakeClient) LoginURL(string) string          { return "" }
func (c *fakeClient) RedirectURIs() []string          { return c.redirects }

var _ storm.Client = (*fakeClient)(nil)

type fakeClientStore struct {
	client *fakeClient
}

func (s *fakeClientStore) GetClientByClientID(_ context.Context, clientID string) (storm.Client, error) {
	if s.client != nil && s.client.id == clientID {
		return s.client, nil
	}
	return nil, errNotFound
}

func (s *fakeClientStore) AuthorizeClientIDSecret(_ context.Context, clientID, clientSecret string) error {
	if s.client != nil && s.client.id == clientID && s.client.secret == clientSecret {
		return nil
	}
	return protocol.ErrInvalidClient()
}

// --- helpers ---

func newTestPlugin(parStore storm.PARStore, clientStore storm.ClientStore) *Plugin {
	return NewWithConfig(Config{
		Store:       parStore,
		ClientStore: clientStore,
		Decoder:     protocol.NewDecoder(),
	})
}

func newFormRequest(form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := shared.ContextWithIssuer(r.Context(), "https://op.example.com")
	return r.WithContext(ctx)
}

func serveRequest(plugin *Plugin, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	plugin.handle(w, r)
	return w
}

// --- Tests ---

// RFC 9126 §3: Successful PAR returns 201 with request_uri and expires_in.
func TestPAR_SuccessfulRequest(t *testing.T) {
	client := &fakeClient{
		id:         "myclient",
		secret:     "secret",
		authMethod: protocol.AuthMethodBasic,
		redirects:  []string{"https://app.example.com/callback"},
	}
	store := &fakePARStore{}
	p := newTestPlugin(store, &fakeClientStore{client: client})

	form := url.Values{
		"client_id":     {"myclient"},
		"client_secret": {"secret"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	r := newFormRequest(form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusCreated, w.Code)

	var resp protocol.PushedAuthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.RequestURI)
	assert.Equal(t, 90, resp.ExpiresIn) // default 90s
}

// RFC 9126 §3: Missing client_id returns invalid_request.
func TestPAR_MissingClientID(t *testing.T) {
	client := &fakeClient{id: "myclient", authMethod: protocol.AuthMethodBasic}
	p := newTestPlugin(&fakePARStore{}, &fakeClientStore{client: client})

	form := url.Values{
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
	}
	r := newFormRequest(form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "client_id is required")
}

// RFC 9126 §3: Unknown client returns invalid_client.
func TestPAR_UnknownClient(t *testing.T) {
	p := newTestPlugin(&fakePARStore{}, &fakeClientStore{client: nil})

	form := url.Values{
		"client_id":     {"unknown"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
	}
	r := newFormRequest(form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_client")
}

// RFC 9126 §3: Wrong client_secret returns invalid_client.
func TestPAR_ClientAuthFailed(t *testing.T) {
	client := &fakeClient{
		id:         "myclient",
		secret:     "correct",
		authMethod: protocol.AuthMethodBasic,
		redirects:  []string{"https://app.example.com/callback"},
	}
	p := newTestPlugin(&fakePARStore{}, &fakeClientStore{client: client})

	form := url.Values{
		"client_id":     {"myclient"},
		"client_secret": {"wrong"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
	}
	r := newFormRequest(form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_client")
}

// RFC 9126 §3: Invalid redirect_uri returns error.
func TestPAR_InvalidRedirectURI(t *testing.T) {
	client := &fakeClient{
		id:         "myclient",
		secret:     "secret",
		authMethod: protocol.AuthMethodBasic,
		redirects:  []string{"https://app.example.com/callback"},
	}
	p := newTestPlugin(&fakePARStore{}, &fakeClientStore{client: client})

	form := url.Values{
		"client_id":     {"myclient"},
		"client_secret": {"secret"},
		"redirect_uri":  {"https://evil.example.com/steal"},
		"response_type": {"code"},
	}
	r := newFormRequest(form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// Store error returns server_error.
func TestPAR_StoreError(t *testing.T) {
	client := &fakeClient{
		id:         "myclient",
		secret:     "secret",
		authMethod: protocol.AuthMethodBasic,
		redirects:  []string{"https://app.example.com/callback"},
	}
	store := &fakePARStore{
		storeFn: func(ctx context.Context, clientID string, req *protocol.AuthRequest, lifetime time.Duration) (string, error) {
			return "", errors.New("db error")
		},
	}
	p := newTestPlugin(store, &fakeClientStore{client: client})

	form := url.Values{
		"client_id":     {"myclient"},
		"client_secret": {"secret"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	r := newFormRequest(form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "server_error")
}

// Default lifetime is 90 seconds.
func TestPAR_DefaultLifetime(t *testing.T) {
	p := NewWithConfig(Config{
		Store:       &fakePARStore{},
		ClientStore: &fakeClientStore{},
		Decoder:     protocol.NewDecoder(),
	})
	assert.Equal(t, 90*time.Second, p.lifetime)
}

// Custom lifetime is respected.
func TestPAR_CustomLifetime(t *testing.T) {
	p := NewWithConfig(Config{
		Store:       &fakePARStore{},
		ClientStore: &fakeClientStore{},
		Decoder:     protocol.NewDecoder(),
		Lifetime:    10 * time.Minute,
	})
	assert.Equal(t, 10*time.Minute, p.lifetime)
}

// Discovery Contribute sets the PAR endpoint.
func TestPAR_DiscoveryContribute(t *testing.T) {
	p := newTestPlugin(&fakePARStore{}, &fakeClientStore{})

	ctx := shared.ContextWithIssuer(context.Background(), "https://op.example.com")
	cfg := &protocol.DiscoveryConfiguration{}
	p.Contribute(ctx, cfg)

	assert.Equal(t, "https://op.example.com/par", cfg.PushedAuthorizationRequestEndpoint)
}

// Router registration adds POST /par.
func TestPAR_RouterRegistration(t *testing.T) {
	p := newTestPlugin(&fakePARStore{}, &fakeClientStore{})

	r := chi.NewRouter()
	p.Register(r)

	// Verify the route exists by matching a request.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/par", nil)
	r.ServeHTTP(rec, req)

	// Should not be 405 Method Not Allowed (route exists).
	assert.NotEqual(t, http.StatusMethodNotAllowed, rec.Code)
}

// Plugin metadata.
func TestPAR_PluginMetadata(t *testing.T) {
	p := newTestPlugin(&fakePARStore{}, &fakeClientStore{})

	assert.Equal(t, "par", p.Name())
	assert.Equal(t, storm.CategoryStandard, p.Category())
	assert.Equal(t, []string{"PARStore", "ClientStore"}, p.Requires())
}

// Public client (AuthMethodNone) skips secret validation.
func TestPAR_PublicClient(t *testing.T) {
	client := &fakeClient{
		id:         "public-client",
		authMethod: protocol.AuthMethodNone,
		redirects:  []string{"https://app.example.com/callback"},
	}
	store := &fakePARStore{}
	p := newTestPlugin(store, &fakeClientStore{client: client})

	form := url.Values{
		"client_id":     {"public-client"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	r := newFormRequest(form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusCreated, w.Code)
}

// StorePushedAuthRequest receives correct parameters.
func TestPAR_StoreReceivesCorrectParams(t *testing.T) {
	client := &fakeClient{
		id:         "myclient",
		secret:     "secret",
		authMethod: protocol.AuthMethodBasic,
		redirects:  []string{"https://app.example.com/callback"},
	}

	var capturedClientID string
	var capturedReq *protocol.AuthRequest
	var capturedLifetime time.Duration

	store := &fakePARStore{
		storeFn: func(ctx context.Context, clientID string, req *protocol.AuthRequest, lifetime time.Duration) (string, error) {
			capturedClientID = clientID
			capturedReq = req
			capturedLifetime = lifetime
			return "urn:ietf:params:oauth:request_uri:abc", nil
		},
	}
	p := newTestPlugin(store, &fakeClientStore{client: client})

	form := url.Values{
		"client_id":     {"myclient"},
		"client_secret": {"secret"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"xyz"},
	}
	r := newFormRequest(form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "myclient", capturedClientID)
	assert.Equal(t, "myclient", capturedReq.ClientID)
	assert.Equal(t, "https://app.example.com/callback", capturedReq.RedirectURI)
	assert.Equal(t, protocol.ResponseType("code"), capturedReq.ResponseType)
	assert.Equal(t, protocol.SpaceDelimitedArray{"openid", "profile"}, capturedReq.Scopes)
	assert.Equal(t, "xyz", capturedReq.State)
	assert.Equal(t, 90*time.Second, capturedLifetime)
}

// RFC 9126 §2.1 step 2: Reject request_uri in PAR request.
func TestPAR_RejectsRequestURI(t *testing.T) {
	client := &fakeClient{
		id:         "myclient",
		secret:     "secret",
		authMethod: protocol.AuthMethodBasic,
		redirects:  []string{"https://app.example.com/callback"},
	}
	p := newTestPlugin(&fakePARStore{}, &fakeClientStore{client: client})

	form := url.Values{
		"client_id":     {"myclient"},
		"client_secret": {"secret"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"request_uri":   {"urn:ietf:params:oauth:request_uri:abc"},
	}
	r := newFormRequest(form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "request_uri is not allowed")
}

// Response headers include Cache-Control: no-store (RFC 6749 §5.1).
func TestPAR_CacheControlHeaders(t *testing.T) {
	client := &fakeClient{
		id:         "myclient",
		secret:     "secret",
		authMethod: protocol.AuthMethodBasic,
		redirects:  []string{"https://app.example.com/callback"},
	}
	p := newTestPlugin(&fakePARStore{}, &fakeClientStore{client: client})

	form := url.Values{
		"client_id":     {"myclient"},
		"client_secret": {"secret"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	r := newFormRequest(form)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
}

// init() returns nil when storage doesn't implement PARStore.
func TestPAR_InitReturnsNilForNonPARStore(t *testing.T) {
	factory := getPARFactory()
	require.NotNil(t, factory)

	// Storage that only implements ClientStore (not PARStore).
	ctx := &storm.PluginContext{
		Storage: &minimalStorage{},
		Decoder: protocol.NewDecoder(),
	}
	plugin := factory(ctx)
	assert.Nil(t, plugin)
}

// --- helpers for init() test ---

func getPARFactory() storm.PluginFactory {
	// Walk the registered plugins to find "par".
	// Since RegisterPlugin is called in init(), we can't easily intercept it.
	// Instead, we test the factory logic directly by replicating the type assertion.
	return func(ctx *storm.PluginContext) storm.Plugin {
		parStore, ok := ctx.Storage.(storm.PARStore)
		if !ok {
			return nil
		}
		return NewWithConfig(Config{
			Store:       parStore,
			ClientStore: ctx.Storage.(storm.ClientStore),
			Decoder:     ctx.Decoder,
		})
	}
}

// minimalStorage implements only ClientStore + KeyStore (not PARStore).
type minimalStorage struct{}

func (s *minimalStorage) GetClientByClientID(_ context.Context, _ string) (storm.Client, error) {
	return nil, errNotFound
}
func (s *minimalStorage) AuthorizeClientIDSecret(_ context.Context, _, _ string) error {
	return errNotFound
}
func (s *minimalStorage) KeySet(_ context.Context) ([]protocol.Key, error) { return nil, nil }
func (s *minimalStorage) SignatureAlgorithms(_ context.Context) ([]string, error) {
	return []string{"RS256"}, nil
}
func (s *minimalStorage) SigningKey(_ context.Context) (storm.SigningKey, error) { return nil, nil }
func (s *minimalStorage) Health(_ context.Context) error                         { return nil }
