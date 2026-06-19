package endsession

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
)

// --- fakes ---

type fakeSessionStore struct {
	terminated []struct{ userID, clientID string }
}

func (s *fakeSessionStore) TerminateSession(_ context.Context, userID, clientID string) error {
	s.terminated = append(s.terminated, struct{ userID, clientID string }{userID, clientID})
	return nil
}

type fakeClient struct {
	id                 string
	postLogoutRedirect []string
}

func (c *fakeClient) GetID() string                    { return c.id }
func (c *fakeClient) AuthMethod() protocol.AuthMethod  { return protocol.AuthMethodNone }
func (c *fakeClient) LoginURL(id string) string        { return "/login?id=" + id }
func (c *fakeClient) PostLogoutRedirectURIs() []string { return c.postLogoutRedirect }

type fakeClientStore struct {
	clients map[string]*fakeClient
}

func (s *fakeClientStore) GetClientByClientID(_ context.Context, clientID string) (storm.Client, error) {
	c, ok := s.clients[clientID]
	if !ok {
		return nil, protocol.ErrInvalidClient()
	}
	return c, nil
}

func (s *fakeClientStore) AuthorizeClientIDSecret(_ context.Context, _, _ string) error {
	return nil
}

type fakeLogoutHook struct {
	called []struct{ userID, clientID, sid string }
}

func (h *fakeLogoutHook) PostLogout(_ context.Context, userID, clientID, sid string) {
	h.called = append(h.called, struct{ userID, clientID, sid string }{userID, clientID, sid})
}

// --- helpers ---

func newTestPlugin(t *testing.T, ss *fakeSessionStore, cs *fakeClientStore) *Plugin {
	t.Helper()
	return &Plugin{
		store:       ss,
		clientStore: cs,
		keyStore:    nil,
		decoder:     protocol.NewDecoder(),
		logoutTmpl:  logoutTmpl,
	}
}

// --- tests ---

func TestName(t *testing.T) {
	p := newTestPlugin(t, &fakeSessionStore{}, &fakeClientStore{})
	assert.Equal(t, "endsession", p.Name())
}

func TestCategory(t *testing.T) {
	p := newTestPlugin(t, &fakeSessionStore{}, &fakeClientStore{})
	assert.Equal(t, storm.CategoryStandard, p.Category())
}

func TestRequires(t *testing.T) {
	p := newTestPlugin(t, &fakeSessionStore{}, &fakeClientStore{})
	assert.Equal(t, []string{"SessionStore", "ClientStore", "KeyStore"}, p.Requires())
}

func TestContribute(t *testing.T) {
	p := newTestPlugin(t, &fakeSessionStore{}, &fakeClientStore{})
	cfg := &protocol.DiscoveryConfiguration{Extra: make(map[string]any)}
	ctx := context.Background()
	p.Contribute(ctx, cfg)
	assert.Contains(t, cfg.EndSessionEndpoint, "/end_session")
}

func TestHandle_NoIdTokenHint_ShowsLogoutPage(t *testing.T) {
	ss := &fakeSessionStore{}
	p := newTestPlugin(t, ss, &fakeClientStore{})

	r := httptest.NewRequest(http.MethodGet, "/end_session", nil)
	w := httptest.NewRecorder()

	p.handle(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "logged out")
	// Session termination is called even with empty userID/clientID
	require.Len(t, ss.terminated, 1)
	assert.Equal(t, "", ss.terminated[0].userID)
}

func TestHandle_WithClientIdAndState_ShowsLogoutPage(t *testing.T) {
	ss := &fakeSessionStore{}
	p := newTestPlugin(t, ss, &fakeClientStore{})

	r := httptest.NewRequest(http.MethodGet, "/end_session?client_id=test-client&state=xyz", nil)
	w := httptest.NewRecorder()

	p.handle(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "logged out")
}

func TestHandle_InvalidRedirectURI_ShowsErrorPage(t *testing.T) {
	ss := &fakeSessionStore{}
	cs := &fakeClientStore{
		clients: map[string]*fakeClient{
			"client1": {id: "client1", postLogoutRedirect: []string{"https://example.com/logout"}},
		},
	}
	p := newTestPlugin(t, ss, cs)

	// client_id present with unregistered redirect URI → error page (400)
	r := httptest.NewRequest(http.MethodGet, "/end_session?client_id=client1&post_logout_redirect_uri=https://evil.com/logout", nil)
	w := httptest.NewRecorder()

	p.handle(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid post_logout_redirect_uri")
}

func TestHandle_ContributeDiscovery(t *testing.T) {
	p := newTestPlugin(t, &fakeSessionStore{}, &fakeClientStore{})
	cfg := &protocol.DiscoveryConfiguration{Extra: make(map[string]any)}
	p.Contribute(context.Background(), cfg)

	require.NotEmpty(t, cfg.EndSessionEndpoint)
	assert.True(t, strings.HasSuffix(cfg.EndSessionEndpoint, "/end_session"))
}

func TestHandle_POST_NoIdTokenHint_ShowsLogoutPage(t *testing.T) {
	ss := &fakeSessionStore{}
	p := newTestPlugin(t, ss, &fakeClientStore{})

	r := httptest.NewRequest(http.MethodPost, "/end_session", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handle(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "logged out")
}

func TestNew_WithConfig(t *testing.T) {
	ss := &fakeSessionStore{}
	cs := &fakeClientStore{}
	cfg := Config{
		Store:            ss,
		ClientStore:      cs,
		KeyStore:         nil,
		DefaultLogoutURI: "/goodbye",
		Decoder:          protocol.NewDecoder(),
	}
	p := NewWithConfig(cfg)
	assert.Equal(t, "endsession", p.Name())
	assert.Equal(t, "/goodbye", p.defaultLogoutURI)
}

func TestLogoutHook_CalledOnLogout(t *testing.T) {
	hook := &fakeLogoutHook{}
	ss := &fakeSessionStore{}
	p := &Plugin{
		store:       ss,
		clientStore: &fakeClientStore{},
		keyStore:    nil,
		decoder:     protocol.NewDecoder(),
		logoutHook:  hook,
		logoutTmpl:  logoutTmpl,
	}

	// Without id_token_hint, logoutHook is still called (handler always terminates session)
	r := httptest.NewRequest(http.MethodGet, "/end_session", nil)
	w := httptest.NewRecorder()
	p.handle(w, r)

	require.Len(t, hook.called, 1)
	assert.Equal(t, "", hook.called[0].userID)
	assert.Equal(t, "", hook.called[0].sid)
}
