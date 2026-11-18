package storm_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/shared"
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

// --- signing key rotation ---

type testKey struct{ id string }

func (k *testKey) ID() string        { return k.id }
func (k *testKey) Algorithm() string { return "RS256" }
func (k *testKey) Use() string       { return "sig" }
func (k *testKey) Key() jwk.Key      { return nil }

type rotatingStorage struct {
	*stubStorage
	signingKey *testKey
	keySet     []storm.Key
	dropNewKey bool
}

func (s *rotatingStorage) SigningKey(context.Context) (storm.SigningKey, error) {
	return s.signingKey, nil
}

func (s *rotatingStorage) KeySet(context.Context) ([]storm.Key, error) {
	return s.keySet, nil
}

func (s *rotatingStorage) RotateSigningKey(context.Context) (string, error) {
	old := s.signingKey
	s.signingKey = &testKey{id: "new"}
	if s.dropNewKey {
		s.keySet = []storm.Key{old}
	} else {
		s.keySet = []storm.Key{old, s.signingKey}
	}
	return "new", nil
}

func TestEngine_RotateSigningKeyUnsupported(t *testing.T) {
	engine := storm.New(&stubStorage{}, shared.StaticIssuer("https://example.com"))

	if _, err := engine.RotateSigningKey(context.Background()); !errors.Is(err, storm.ErrSigningKeyRotationUnsupported) {
		t.Fatalf("err = %v, want ErrSigningKeyRotationUnsupported", err)
	}
}

func TestEngine_RotateSigningKey(t *testing.T) {
	store := &rotatingStorage{
		stubStorage: &stubStorage{},
		signingKey:  &testKey{id: "old"},
		keySet:      []storm.Key{&testKey{id: "old"}},
	}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	id, err := engine.RotateSigningKey(context.Background())
	if err != nil {
		t.Fatalf("RotateSigningKey() error = %v", err)
	}
	if id != "new" {
		t.Fatalf("RotateSigningKey() = %q, want %q", id, "new")
	}
}

func TestEngine_RotateSigningKeyRequiresKeyInSet(t *testing.T) {
	store := &rotatingStorage{
		stubStorage: &stubStorage{},
		signingKey:  &testKey{id: "old"},
		keySet:      []storm.Key{&testKey{id: "old"}},
		dropNewKey:  true,
	}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	_, err := engine.RotateSigningKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "missing from KeySet") {
		t.Fatalf("err = %v, want missing-from-KeySet error", err)
	}
}

// --- minimal plugin ---

type helloPlugin struct{}

func (p *helloPlugin) Name() string { return "hello" }

func (p *helloPlugin) Register(r chi.Router) {
	r.Get("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})
}

// categorizedPlugin declares its category only via CategorizablePlugin, which
// exercises the fallback path used by WithPlugin factories.
type categorizedPlugin struct {
	name     string
	category storm.PluginCategory
}

func (p *categorizedPlugin) Name() string { return p.name }

func (p *categorizedPlugin) Register(r chi.Router) {
	r.Get("/"+p.name, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(p.name))
	})
}

func (p *categorizedPlugin) Category() storm.PluginCategory {
	return p.category
}

func (p *categorizedPlugin) Requires() []storm.StorageCapability {
	return nil
}

// --- discovery contributor ---

type contribPlugin struct {
	name string
	fn   func(ctx context.Context, cfg *protocol.DiscoveryConfiguration)
}

func (p *contribPlugin) Name() string { return p.name }

func (p *contribPlugin) Register(r chi.Router) {
	r.Get("/"+p.name, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(p.name))
	})
}

func (p *contribPlugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	if p.fn != nil {
		p.fn(ctx, cfg)
	}
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
	engine.Register(&contribPlugin{name: "auth", fn: func(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
		cfg.AuthorizationEndpoint = "https://example.com/authorize"
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

func TestEngineDiscoveryOverride(t *testing.T) {
	// Later plugins can override fields set by earlier plugins.
	store := &stubStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))
	engine.Register(&contribPlugin{name: "a", fn: func(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
		cfg.AuthorizationEndpoint = "https://a.com/authorize"
	}})
	engine.Register(&contribPlugin{name: "b", fn: func(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
		cfg.AuthorizationEndpoint = "https://b.com/authorize"
	}})
	handler := engine.Build()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// Last writer wins
	if body["authorization_endpoint"] != "https://b.com/authorize" {
		t.Errorf("authorization_endpoint = %v, want https://b.com/authorize", body["authorization_endpoint"])
	}
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

func (p *optionalPlugin) Requires() []storm.StorageCapability {
	return nil
}

func TestEngineEnableOptionalPlugin(t *testing.T) {
	// Optional plugin factory provided explicitly via WithPlugins.
	factory := storm.NamedPluginFactory{
		Name:     "test_optional",
		Priority: 9999,
		Factory: func(ctx *storm.PluginContext) storm.Plugin {
			return &optionalPlugin{name: "test_optional"}
		},
	}

	t.Run("optional plugin skipped by default", func(t *testing.T) {
		store := &stubStorage{}
		engine := storm.New(store, shared.StaticIssuer("https://example.com"), storm.WithPlugins(factory))
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
			storm.WithPlugins(factory),
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

func TestEngine_DisableCorePluginPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when disabling a core plugin")
		}
	}()

	storm.New(&stubStorage{}, shared.StaticIssuer("https://example.com"),
		storm.WithPlugins(storm.NamedPluginFactory{
			Name:     "core_test",
			Priority: 1,
			Category: storm.CategoryCore,
			Factory: func(*storm.PluginContext) storm.Plugin {
				return &categorizedPlugin{name: "core_test", category: storm.CategoryCore}
			},
		}),
		storm.Disable("core_test"),
	)
}

func TestEngine_DisableCorePluginDeclaredByPluginPanics(t *testing.T) {
	// No descriptor category: the engine must resolve it from the plugin.
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when disabling a core plugin that only declares it via CategorizablePlugin")
		}
	}()

	storm.New(&stubStorage{}, shared.StaticIssuer("https://example.com"),
		storm.WithPlugin(func(*storm.PluginContext) storm.Plugin {
			return &categorizedPlugin{name: "core_anon", category: storm.CategoryCore}
		}),
		storm.Disable("core_anon"),
	)
}

func TestEngine_DisableUsesResolvedPluginName(t *testing.T) {
	// WithPlugin factories share the "custom" placeholder, so Disable must match
	// the instantiated plugin's own name rather than the placeholder.
	engine := storm.New(&stubStorage{}, shared.StaticIssuer("https://example.com"),
		storm.WithPlugin(func(*storm.PluginContext) storm.Plugin {
			return &categorizedPlugin{name: "anon_disabled", category: storm.CategoryStandard}
		}),
		storm.Disable("anon_disabled"),
	)

	if got := len(engine.Plugins()); got != 0 {
		t.Fatalf("disabled anonymous plugin was registered (plugins=%d)", got)
	}
}

func TestEngine_OptionalAnonymousPluginEnabledByPluginName(t *testing.T) {
	factory := func(*storm.PluginContext) storm.Plugin {
		return &optionalPlugin{name: "anon_optional"}
	}

	t.Run("skipped by default", func(t *testing.T) {
		engine := storm.New(&stubStorage{}, shared.StaticIssuer("https://example.com"),
			storm.WithPlugin(factory))
		if got := len(engine.Plugins()); got != 0 {
			t.Fatalf("optional plugin registered without Enable() (plugins=%d)", got)
		}
	})

	t.Run("enabled by plugin name", func(t *testing.T) {
		engine := storm.New(&stubStorage{}, shared.StaticIssuer("https://example.com"),
			storm.WithPlugin(factory),
			storm.Enable("anon_optional"))
		if got := len(engine.Plugins()); got != 1 {
			t.Fatalf("Enable(plugin name) did not register the plugin (plugins=%d)", got)
		}
	})
}

func TestEngine_DuplicatePluginNamePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate plugin names")
		}
	}()

	storm.New(&stubStorage{}, shared.StaticIssuer("https://example.com"),
		storm.WithPlugin(func(*storm.PluginContext) storm.Plugin {
			return &categorizedPlugin{name: "dup", category: storm.CategoryStandard}
		}),
		storm.WithPlugin(func(*storm.PluginContext) storm.Plugin {
			return &categorizedPlugin{name: "dup", category: storm.CategoryStandard}
		}),
	)
}

func TestEngine_UnknownDisableNameIsIgnored(t *testing.T) {
	// A name that is compiled out (e.g. an EE build tag) is not an error.
	engine := storm.New(&stubStorage{}, shared.StaticIssuer("https://example.com"),
		storm.WithPlugins(storm.NamedPluginFactory{
			Name:     "present",
			Priority: 1,
			Factory: func(*storm.PluginContext) storm.Plugin {
				return &categorizedPlugin{name: "present", category: storm.CategoryStandard}
			},
		}),
		storm.Disable("compiled_out"),
	)

	if got := len(engine.Plugins()); got != 1 {
		t.Fatalf("unexpected plugin count after unknown Disable name: %d", got)
	}
}

func TestRegisterPlugin_DuplicateNamePanics(t *testing.T) {
	storm.RegisterPlugin("dup_register_test", 1, func(*storm.PluginContext) storm.Plugin {
		return &helloPlugin{}
	})

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate RegisterPlugin")
		}
	}()
	storm.RegisterPlugin("dup_register_test", 1, func(*storm.PluginContext) storm.Plugin {
		return &helloPlugin{}
	})
}
