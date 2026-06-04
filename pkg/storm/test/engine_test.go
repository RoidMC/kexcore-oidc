package storm_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// --- minimal storage stub ---

type stubStorage struct{}

func (s *stubStorage) GetClientByClientID(ctx context.Context, clientID string) (storm.Client, error) {
	return nil, errors.New("not found")
}

func (s *stubStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	return errors.New("not implemented")
}

func (s *stubStorage) KeySet(ctx context.Context) ([]storm.Key, error) {
	return nil, nil
}

func (s *stubStorage) SignatureAlgorithms(ctx context.Context) ([]string, error) {
	return []string{"RS256"}, nil
}

func (s *stubStorage) SigningKey(ctx context.Context) (storm.SigningKey, error) {
	return nil, errors.New("not implemented")
}

func (s *stubStorage) Health(ctx context.Context) error {
	return nil
}

// --- minimal plugin ---

type helloPlugin struct{}

func (p *helloPlugin) Name() string { return "hello" }

func (p *helloPlugin) Register(r chi.Router) {
	r.Get("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})
}

// --- discovery contributor ---

type contribPlugin struct {
	name string
	kv   map[string]any
}

func (p *contribPlugin) Name() string { return p.name }

func (p *contribPlugin) Register(r chi.Router) {
	r.Get("/"+p.name, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(p.name))
	})
}

func (p *contribPlugin) Contribute(ctx context.Context) map[string]any {
	return p.kv
}

// --- tests ---

func TestEngineRegisterAndServe(t *testing.T) {
	store := &stubStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))
	engine.Register(&helloPlugin{})

	handler := engine.Build()

	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "hello" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "hello")
	}
}

func TestEngineHealthz(t *testing.T) {
	store := &stubStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))
	handler := engine.Build()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want ok", body["status"])
	}
}

func TestEngineReady(t *testing.T) {
	store := &stubStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))
	handler := engine.Build()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestEngineDiscovery(t *testing.T) {
	store := &stubStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))
	engine.Register(&contribPlugin{name: "auth", kv: map[string]any{
		"authorization_endpoint": "https://example.com/authorize",
	}})
	handler := engine.Build()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["issuer"] != "https://example.com" {
		t.Errorf("issuer = %v, want https://example.com", body["issuer"])
	}
	if body["authorization_endpoint"] != "https://example.com/authorize" {
		t.Errorf("authorization_endpoint = %v", body["authorization_endpoint"])
	}
}

func TestEngineDiscoveryCollision(t *testing.T) {
	store := &stubStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))
	engine.Register(&contribPlugin{name: "a", kv: map[string]any{
		"authorization_endpoint": "https://a.com/authorize",
	}})
	engine.Register(&contribPlugin{name: "b", kv: map[string]any{
		"authorization_endpoint": "https://b.com/authorize",
	}})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for discovery key collision")
		}
	}()
	engine.Build()
}

func TestEngineHandlerBeforeBuild(t *testing.T) {
	store := &stubStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for Handler() before Build()")
		}
	}()
	engine.Handler()
}

func TestEngineMiddleware(t *testing.T) {
	store := &stubStorage{}
	called := false
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			next.ServeHTTP(w, r)
		})
	}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"), storm.WithMiddleware(mw))
	engine.Register(&helloPlugin{})
	handler := engine.Build()

	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("middleware was not called")
	}
}

// --- optional plugin stub ---

type optionalPlugin struct {
	name string
}

func (p *optionalPlugin) Name() string { return p.name }

func (p *optionalPlugin) Register(r chi.Router) {
	r.Get("/"+p.name, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(p.name))
	})
}

func (p *optionalPlugin) Category() storm.PluginCategory {
	return storm.CategoryOptional
}

func (p *optionalPlugin) Requires() []string {
	return nil
}

func TestEngineEnableOptionalPlugin(t *testing.T) {
	// Register an optional plugin factory
	storm.RegisterPlugin("test_optional", 9999, func(ctx *storm.PluginContext) storm.Plugin {
		return &optionalPlugin{name: "test_optional"}
	})

	t.Run("optional plugin skipped by default", func(t *testing.T) {
		store := &stubStorage{}
		engine := storm.New(store, shared.StaticIssuer("https://example.com"))
		handler := engine.Build()

		req := httptest.NewRequest(http.MethodGet, "/test_optional", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// Optional plugin should not be registered, so we get 404
		if rec.Code != http.StatusNotFound {
			t.Errorf("expected 404 for optional plugin, got %d", rec.Code)
		}
	})

	t.Run("optional plugin enabled via Enable()", func(t *testing.T) {
		store := &stubStorage{}
		engine := storm.New(store, shared.StaticIssuer("https://example.com"),
			storm.Enable("test_optional"))
		handler := engine.Build()

		req := httptest.NewRequest(http.MethodGet, "/test_optional", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// Optional plugin should be registered and accessible
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 for enabled optional plugin, got %d", rec.Code)
		}
		if rec.Body.String() != "test_optional" {
			t.Errorf("body = %q, want %q", rec.Body.String(), "test_optional")
		}
	})
}