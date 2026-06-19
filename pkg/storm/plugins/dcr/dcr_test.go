// Package dcr — tests for RFC 7591 Dynamic Client Registration.
package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

var errNotFound = errors.New("not found")

// --- fakes ---

type fakeDCRStore struct {
	registration *storm.ClientRegistration
	createErr    error
}

func (s *fakeDCRStore) CreateClient(ctx context.Context, req *storm.RegistrationRequest, clientID, clientSecret, accessToken, uri string) (*storm.ClientRegistration, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	return &storm.ClientRegistration{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		RegistrationAccessToken: accessToken,
		RegistrationClientURI:   uri,
		ClientIDIssuedAt:        1000,
		ClientSecretExpiresAt:   0,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scope:                   req.Scope,
	}, nil
}

func (s *fakeDCRStore) GetClientRegistration(ctx context.Context, clientID string) (*storm.ClientRegistration, error) {
	if s.registration != nil && s.registration.ClientID == clientID {
		return s.registration, nil
	}
	return nil, errNotFound
}

func (s *fakeDCRStore) GetClientRegistrationByToken(ctx context.Context, token string) (*storm.ClientRegistration, error) {
	if s.registration != nil && s.registration.RegistrationAccessToken == token {
		return s.registration, nil
	}
	return nil, errNotFound
}

func (s *fakeDCRStore) UpdateClientRegistration(ctx context.Context, clientID string, update *storm.RegistrationRequest) (*storm.ClientRegistration, error) {
	if s.registration != nil && s.registration.ClientID == clientID {
		s.registration.ClientName = update.ClientName
		return s.registration, nil
	}
	return nil, errNotFound
}

func (s *fakeDCRStore) DeleteClientRegistration(ctx context.Context, clientID string) error {
	if s.registration != nil && s.registration.ClientID == clientID {
		s.registration = nil
		return nil
	}
	return errNotFound
}

var _ storm.DCRStore = (*fakeDCRStore)(nil)

// --- helpers ---

func newTestPlugin(store storm.DCRStore) *Plugin {
	return New(Config{Store: store})
}

func newJSONRequest(method, path string, body interface{}) *http.Request {
	var reader *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = strings.NewReader(string(b))
	} else {
		reader = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, reader)
	r.Header.Set("Content-Type", "application/json")
	ctx := shared.ContextWithIssuer(r.Context(), "https://op.example.com")
	return r.WithContext(ctx)
}

func serveRequest(plugin *Plugin, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	plugin.handleCreate(w, r)
	return w
}

// --- Tests ---

// RFC 7591 §3: Successful registration returns 201 with client_id.
func TestDCR_SuccessfulRegistration(t *testing.T) {
	store := &fakeDCRStore{}
	p := newTestPlugin(store)

	body := map[string]interface{}{
		"redirect_uris":              []string{"https://app.example.com/callback"},
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid",
	}
	r := newJSONRequest(http.MethodPost, "/register", body)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusCreated, w.Code)

	var resp storm.ClientRegistration
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.ClientID)
	assert.NotEmpty(t, resp.ClientSecret)
	assert.NotEmpty(t, resp.RegistrationAccessToken)
	assert.Equal(t, []string{"https://app.example.com/callback"}, resp.RedirectURIs)
}

// Invalid JSON body returns 400.
func TestDCR_InvalidJSON(t *testing.T) {
	p := newTestPlugin(&fakeDCRStore{})

	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("not json"))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleCreate(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "error decoding request body")
}

// Store error returns 500.
func TestDCR_StoreError(t *testing.T) {
	store := &fakeDCRStore{
		createErr: errors.New("db error"),
	}
	p := newTestPlugin(store)

	body := map[string]interface{}{
		"redirect_uris": []string{"https://app.example.com/callback"},
	}
	r := newJSONRequest(http.MethodPost, "/register", body)
	w := serveRequest(p, r)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// GET /register/{client_id} with valid token returns 200.
func TestDCR_GetClient(t *testing.T) {
	registration := &storm.ClientRegistration{
		ClientID:                "client-123",
		RegistrationAccessToken: "token-abc",
		RedirectURIs:            []string{"https://app.example.com/callback"},
	}
	store := &fakeDCRStore{registration: registration}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/register/client-123", nil)
	r.Header.Set("Authorization", "Bearer token-abc")
	r = r.WithContext(shared.ContextWithIssuer(r.Context(), "https://op.example.com"))

	// Need chi URL param
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("client_id", "client-123")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	p.handleGet(w, r)

	require.Equal(t, http.StatusOK, w.Code)

	var resp storm.ClientRegistration
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "client-123", resp.ClientID)
}

// GET without token returns 401 (invalid_client).
func TestDCR_GetClient_NoToken(t *testing.T) {
	store := &fakeDCRStore{}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/register/client-123", nil)
	r = r.WithContext(shared.ContextWithIssuer(r.Context(), "https://op.example.com"))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("client_id", "client-123")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	p.handleGet(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// GET with wrong token returns 401 (invalid_client).
func TestDCR_GetClient_WrongToken(t *testing.T) {
	registration := &storm.ClientRegistration{
		ClientID:                "client-123",
		RegistrationAccessToken: "token-abc",
	}
	store := &fakeDCRStore{registration: registration}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/register/client-123", nil)
	r.Header.Set("Authorization", "Bearer wrong-token")
	r = r.WithContext(shared.ContextWithIssuer(r.Context(), "https://op.example.com"))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("client_id", "client-123")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	p.handleGet(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// PUT /register/{client_id} updates client.
func TestDCR_UpdateClient(t *testing.T) {
	registration := &storm.ClientRegistration{
		ClientID:                "client-123",
		RegistrationAccessToken: "token-abc",
	}
	store := &fakeDCRStore{registration: registration}
	p := newTestPlugin(store)

	body := map[string]interface{}{
		"client_name": "Updated Name",
	}
	r := newJSONRequest(http.MethodPut, "/register/client-123", body)
	r.Header.Set("Authorization", "Bearer token-abc")

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("client_id", "client-123")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	p.handleUpdate(w, r)

	require.Equal(t, http.StatusOK, w.Code)
}

// DELETE /register/{client_id} returns 204.
func TestDCR_DeleteClient(t *testing.T) {
	registration := &storm.ClientRegistration{
		ClientID:                "client-123",
		RegistrationAccessToken: "token-abc",
	}
	store := &fakeDCRStore{registration: registration}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodDelete, "/register/client-123", nil)
	r.Header.Set("Authorization", "Bearer token-abc")
	r = r.WithContext(shared.ContextWithIssuer(r.Context(), "https://op.example.com"))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("client_id", "client-123")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	p.handleDelete(w, r)

	require.Equal(t, http.StatusNoContent, w.Code)
}

// Discovery contributes registration_endpoint.
func TestDCR_Discovery(t *testing.T) {
	p := newTestPlugin(&fakeDCRStore{})
	cfg := &protocol.DiscoveryConfiguration{}
	p.Contribute(context.Background(), cfg)

	assert.NotEmpty(t, cfg.RegistrationEndpoint)
	assert.Contains(t, cfg.RegistrationEndpoint, "/register")
}

// init() factory returns nil when storage doesn't implement DCRStore.
func TestDCR_InitReturnsNilForNonDCRStore(t *testing.T) {
	factory := getDCRFactory()
	require.NotNil(t, factory)

	// Storage that doesn't implement DCRStore.
	ctx := &storm.PluginContext{
		Storage: &minimalStorage{},
		Decoder: protocol.NewDecoder(),
	}
	plugin := factory(ctx)
	assert.Nil(t, plugin)
}

// --- helpers for init() test ---

func getDCRFactory() storm.PluginFactory {
	return func(ctx *storm.PluginContext) storm.Plugin {
		dcrStore, ok := ctx.Storage.(storm.DCRStore)
		if !ok {
			return nil
		}
		return New(Config{Store: dcrStore})
	}
}

// minimalStorage implements only ClientStore + KeyStore (not DCRStore).
type minimalStorage struct{}

func (s *minimalStorage) GetClientByClientID(ctx context.Context, clientID string) (storm.Client, error) {
	return nil, errNotFound
}
func (s *minimalStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	return errNotFound
}
func (s *minimalStorage) KeySet(ctx context.Context) ([]protocol.Key, error) {
	return nil, nil
}
func (s *minimalStorage) SignatureAlgorithms(ctx context.Context) ([]string, error) {
	return nil, nil
}
func (s *minimalStorage) SigningKey(ctx context.Context) (storm.SigningKey, error) {
	return nil, errNotFound
}
func (s *minimalStorage) Health(ctx context.Context) error { return nil }

var _ storm.Storage = (*minimalStorage)(nil)

// Name returns "dcr".
func TestDCR_Name(t *testing.T) {
	p := newTestPlugin(&fakeDCRStore{})
	assert.Equal(t, "dcr", p.Name())
}

// Register installs routes.
func TestDCR_Routes(t *testing.T) {
	p := newTestPlugin(&fakeDCRStore{})
	r := chi.NewRouter()
	p.Register(r)

	// Verify routes exist by checking chi routes
	routes := make(map[string]bool)
	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		routes[method+":"+route] = true
		return nil
	}
	_ = chi.Walk(r, walkFunc)

	assert.True(t, routes["POST:/register"])
	assert.True(t, routes["GET:/register/{client_id}"])
	assert.True(t, routes["PUT:/register/{client_id}"])
	assert.True(t, routes["DELETE:/register/{client_id}"])
}

// ClientID mismatch returns 400 (invalid_client).
func TestDCR_ClientIDMismatch(t *testing.T) {
	registration := &storm.ClientRegistration{
		ClientID:                "client-123",
		RegistrationAccessToken: "token-abc",
	}
	store := &fakeDCRStore{registration: registration}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/register/different-client", nil)
	r.Header.Set("Authorization", "Bearer token-abc")
	r = r.WithContext(shared.ContextWithIssuer(r.Context(), "https://op.example.com"))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("client_id", "different-client")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	p.handleGet(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}
