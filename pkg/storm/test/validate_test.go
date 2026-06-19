package storm_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

// --- mock storage with selective interface implementation ---

type baseStorage struct{}

func (s *baseStorage) GetClientByClientID(ctx context.Context, clientID string) (storm.Client, error) {
	return nil, errors.New("not found")
}
func (s *baseStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	return errors.New("not implemented")
}
func (s *baseStorage) KeySet(ctx context.Context) ([]storm.Key, error) { return nil, nil }
func (s *baseStorage) SignatureAlgorithms(ctx context.Context) ([]string, error) {
	return []string{"RS256"}, nil
}
func (s *baseStorage) SigningKey(ctx context.Context) (storm.SigningKey, error) {
	return nil, errors.New("not implemented")
}
func (s *baseStorage) Health(ctx context.Context) error { return nil }

// authStoreStub additionally implements AuthStore
type authStoreStub struct{ baseStorage }

func (s *authStoreStub) CreateAuthRequest(ctx context.Context, req *protocol.AuthRequest, userID string) (storm.AuthRequest, error) {
	return nil, errors.New("not implemented")
}
func (s *authStoreStub) AuthRequestByID(ctx context.Context, id string) (storm.AuthRequest, error) {
	return nil, errors.New("not implemented")
}
func (s *authStoreStub) AuthRequestByCode(ctx context.Context, code string) (storm.AuthRequest, error) {
	return nil, errors.New("not implemented")
}
func (s *authStoreStub) SaveAuthCode(ctx context.Context, id, code string) error {
	return errors.New("not implemented")
}
func (s *authStoreStub) DeleteAuthRequest(ctx context.Context, id string) error {
	return errors.New("not implemented")
}

// tokenStoreStub additionally implements TokenStore
type tokenStoreStub struct{ authStoreStub }

func (s *tokenStoreStub) CreateAccessToken(ctx context.Context, req storm.TokenRequest, cnf map[string]any) (string, time.Time, error) {
	return "", time.Time{}, errors.New("not implemented")
}
func (s *tokenStoreStub) CreateAccessAndRefreshTokens(ctx context.Context, req storm.TokenRequest, currentRefreshToken string, cnf map[string]any) (string, string, time.Time, error) {
	return "", "", time.Time{}, errors.New("not implemented")
}
func (s *tokenStoreStub) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (storm.RefreshTokenRequest, error) {
	return nil, errors.New("not implemented")
}

// fullStoreStub implements all store interfaces (AuthStore + TokenStore + UserinfoStore + KeyStore + SessionStore)
type fullStoreStub struct{ tokenStoreStub }

func (s *fullStoreStub) SetUserinfoFromToken(ctx context.Context, resp *protocol.UserInfo, tokenID, subject, origin string) error {
	return errors.New("not implemented")
}
func (s *fullStoreStub) SetIntrospectionFromToken(ctx context.Context, resp *protocol.IntrospectionResponse, tokenID, subject, clientID string) error {
	return errors.New("not implemented")
}
func (s *fullStoreStub) TerminateSession(ctx context.Context, userID, clientID string) error {
	return errors.New("not implemented")
}
func (s *fullStoreStub) RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *protocol.Error {
	return nil
}

// --- mock plugins ---

type mockPlugin struct {
	name     string
	category storm.PluginCategory
	requires []string
}

func (p *mockPlugin) Name() string { return p.name }
func (p *mockPlugin) Register(r chi.Router) {
	// no-op for test — just registers a dummy route to satisfy the interface
	r.Get("/"+p.name, func(w http.ResponseWriter, r *http.Request) {})
}
func (p *mockPlugin) Category() storm.PluginCategory { return p.category }
func (p *mockPlugin) Requires() []string             { return p.requires }

// --- tests ---

func TestValidate_NilStorage(t *testing.T) {
	engine := storm.New(nil, shared.StaticIssuer("https://example.com"))
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil storage")
		}
	}()
	engine.Build()
}

func TestValidate_StorageMissingAuthStore(t *testing.T) {
	// baseStorage does NOT implement AuthStore
	store := &baseStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	// register a plugin that requires AuthStore
	engine.Register(&mockPlugin{
		name:     "auth",
		category: storm.CategoryCore,
		requires: []string{"AuthStore"},
	})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic: AuthStore not implemented")
		}
	}()
	engine.Build()
}

func TestValidate_StorageSatisfiesAuthStore(t *testing.T) {
	store := &authStoreStub{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	engine.Register(&mockPlugin{
		name:     "auth",
		category: storm.CategoryCore,
		requires: []string{"AuthStore"},
	})

	// Should NOT panic — authStoreStub implements AuthStore
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	engine.Build()
}

func TestValidate_StorageMissingTokenStore(t *testing.T) {
	store := &authStoreStub{} // has AuthStore, NOT TokenStore
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	engine.Register(&mockPlugin{
		name:     "token",
		category: storm.CategoryCore,
		requires: []string{"TokenStore"},
	})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic: TokenStore not implemented")
		}
	}()
	engine.Build()
}

func TestValidate_StorageSatisfiesTokenStore(t *testing.T) {
	store := &tokenStoreStub{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	engine.Register(&mockPlugin{
		name:     "token",
		category: storm.CategoryCore,
		requires: []string{"TokenStore"},
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	engine.Build()
}

func TestValidate_RFCConstraint_AuthNeedsToken(t *testing.T) {
	store := &tokenStoreStub{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	// authorization enabled, token NOT enabled → should fail
	engine.Register(&mockPlugin{
		name:     "authorization",
		category: storm.CategoryCore,
		requires: []string{"AuthStore"},
	})
	// NOTE: token plugin NOT registered

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic: authorization needs token but token not enabled")
		}
	}()
	engine.Build()
}

func TestValidate_RFCConstraint_AuthNeedsUserInfo(t *testing.T) {
	store := &tokenStoreStub{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	engine.Register(&mockPlugin{
		name:     "authorization",
		category: storm.CategoryCore,
		requires: []string{"AuthStore"},
	})
	engine.Register(&mockPlugin{
		name:     "token",
		category: storm.CategoryCore,
		requires: []string{"TokenStore"},
	})
	// userinfo NOT registered

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic: authorization needs userinfo but userinfo not enabled")
		}
	}()
	engine.Build()
}

func TestValidate_RFCConstraint_Pass(t *testing.T) {
	store := &fullStoreStub{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	engine.Register(&mockPlugin{
		name:     "authorization",
		category: storm.CategoryCore,
		requires: []string{"AuthStore"},
	})
	engine.Register(&mockPlugin{
		name:     "token",
		category: storm.CategoryCore,
		requires: []string{"TokenStore"},
	})
	engine.Register(&mockPlugin{
		name:     "userinfo",
		category: storm.CategoryCore,
		requires: []string{"UserinfoStore"},
	})
	engine.Register(&mockPlugin{
		name:     "keys",
		category: storm.CategoryCore,
		requires: []string{"KeyStore"},
	})
	engine.Register(&mockPlugin{
		name:     "endsession",
		category: storm.CategoryCore,
		requires: []string{"SessionStore"},
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	engine.Build()
}

func TestValidate_UnrecognizedInterfaceName(t *testing.T) {
	store := &tokenStoreStub{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	// Unrecognized interface name — should NOT fail
	engine.Register(&mockPlugin{
		name:     "custom",
		category: storm.CategoryCore,
		requires: []string{"SomeUnknownInterface"},
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic for unrecognized interface: %v", r)
		}
	}()
	engine.Build()
}

func TestValidate_ErrorMessageContainsHint(t *testing.T) {
	store := &baseStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	engine.Register(&mockPlugin{
		name:     "token",
		category: storm.CategoryCore,
		requires: []string{"TokenStore"},
	})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value is not string: %v", r)
		}
		if !contains(msg, "CreateAccessToken") {
			t.Errorf("error message should contain method hint, got: %s", msg)
		}
		if !contains(msg, "TokenStore") {
			t.Errorf("error message should contain interface name, got: %s", msg)
		}
		if !contains(msg, "storage.go") {
			t.Errorf("error message should reference storage.go, got: %s", msg)
		}
	}()
	engine.Build()
}

func TestValidate_AuthStoreHint(t *testing.T) {
	store := &baseStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	engine.Register(&mockPlugin{
		name:     "auth",
		category: storm.CategoryCore,
		requires: []string{"AuthStore"},
	})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}
		msg := r.(string)
		if !contains(msg, "CreateAuthRequest") {
			t.Errorf("AuthStore hint should mention CreateAuthRequest, got: %s", msg)
		}
	}()
	engine.Build()
}

func TestValidate_UserinfoStoreHint(t *testing.T) {
	store := &baseStorage{}
	engine := storm.New(store, shared.StaticIssuer("https://example.com"))

	engine.Register(&mockPlugin{
		name:     "userinfo",
		category: storm.CategoryCore,
		requires: []string{"UserinfoStore"},
	})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}
		msg := r.(string)
		if !contains(msg, "SetUserinfoFromToken") {
			t.Errorf("UserinfoStore hint should mention SetUserinfoFromToken, got: %s", msg)
		}
	}()
	engine.Build()
}

// --- optional interface discovery tests ---

// --- helper ---

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
