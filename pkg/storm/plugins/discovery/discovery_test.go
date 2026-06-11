package discovery

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// --- fake KeyStore ---

type fakeKeyStore struct {
	algs []string
	err  error
}

func (s *fakeKeyStore) SignatureAlgorithms(_ context.Context) ([]string, error) {
	return s.algs, s.err
}

func (s *fakeKeyStore) SigningKey(_ context.Context) (storm.SigningKey, error) {
	return nil, nil
}

func (s *fakeKeyStore) KeySet(_ context.Context) ([]protocol.Key, error) {
	return nil, nil
}

// --- tests ---

func newDiscoveryCfg() *protocol.DiscoveryConfiguration {
	return &protocol.DiscoveryConfiguration{
		Extra: make(map[string]any),
	}
}

func TestNew_WithKeyStore(t *testing.T) {
	ks := &fakeKeyStore{algs: []string{"ES256", "PS256"}}
	p := New(ks)
	require.NotNil(t, p)
	assert.Equal(t, "discovery", p.Name())
}

func TestNew_NilKeyStore(t *testing.T) {
	p := New(nil)
	require.NotNil(t, p)
}

func TestNew_WithConfig(t *testing.T) {
	cfg := Config{
		SubjectTypes: []string{"pairwise"},
		ExtraFields:  map[string]any{"custom_field": "value"},
	}
	p := New(nil, cfg)
	assert.Equal(t, []string{"pairwise"}, p.config.SubjectTypes)
	assert.Equal(t, "value", p.config.ExtraFields["custom_field"])
}

func TestContribute_SigningAlgorithms_FromKeyStore(t *testing.T) {
	ks := &fakeKeyStore{algs: []string{"ES256", "PS384"}}
	p := New(ks)
	cfg := newDiscoveryCfg()

	p.Contribute(context.Background(), cfg)

	assert.Equal(t, []string{"ES256", "PS384"}, cfg.IDTokenSigningAlgValuesSupported)
	assert.Equal(t, []string{"ES256", "PS384"}, cfg.UserinfoSigningAlgValuesSupported)
	assert.Equal(t, []string{"ES256", "PS384"}, cfg.RequestObjectSigningAlgValuesSupported)
}

func TestContribute_SigningAlgorithms_FallbackRS256(t *testing.T) {
	t.Run("nil keystore", func(t *testing.T) {
		p := New(nil)
		cfg := newDiscoveryCfg()
		p.Contribute(context.Background(), cfg)
		assert.Equal(t, []string{"RS256"}, cfg.IDTokenSigningAlgValuesSupported)
	})

	t.Run("empty algs", func(t *testing.T) {
		p := New(&fakeKeyStore{algs: []string{}})
		cfg := newDiscoveryCfg()
		p.Contribute(context.Background(), cfg)
		assert.Equal(t, []string{"RS256"}, cfg.IDTokenSigningAlgValuesSupported)
	})

	t.Run("error", func(t *testing.T) {
		p := New(&fakeKeyStore{err: assert.AnError})
		cfg := newDiscoveryCfg()
		p.Contribute(context.Background(), cfg)
		assert.Equal(t, []string{"RS256"}, cfg.IDTokenSigningAlgValuesSupported)
	})
}

func TestContribute_AuthSigningAlgorithms_IncludeHS(t *testing.T) {
	ks := &fakeKeyStore{algs: []string{"ES256"}}
	p := New(ks)
	cfg := newDiscoveryCfg()

	p.Contribute(context.Background(), cfg)

	// Auth signing algs should include HS variants
	authAlgs := cfg.TokenEndpointAuthSigningAlgValuesSupported
	assert.Contains(t, authAlgs, "ES256")
	assert.Contains(t, authAlgs, "HS256")
	assert.Contains(t, authAlgs, "HS384")
	assert.Contains(t, authAlgs, "HS512")

	// Same for introspection and revocation
	assert.Equal(t, authAlgs, cfg.IntrospectionEndpointAuthSigningAlgValuesSupported)
	assert.Equal(t, authAlgs, cfg.RevocationEndpointAuthSigningAlgValuesSupported)
}

func TestContribute_AuthSigningAlgorithms_Sorted(t *testing.T) {
	ks := &fakeKeyStore{algs: []string{"PS256", "ES256"}}
	p := New(ks)
	cfg := newDiscoveryCfg()

	p.Contribute(context.Background(), cfg)

	algs := cfg.TokenEndpointAuthSigningAlgValuesSupported
	// Should be sorted: ES256, HS256, HS384, HS512, PS256
	assert.True(t, sort.StringsAreSorted(algs), "auth signing algs should be sorted: %v", algs)
}

func TestContribute_SubjectTypes_Default(t *testing.T) {
	p := New(nil)
	cfg := newDiscoveryCfg()

	p.Contribute(context.Background(), cfg)

	assert.Equal(t, []string{"public", "pairwise"}, cfg.SubjectTypesSupported)
}

func TestContribute_SubjectTypes_Custom(t *testing.T) {
	p := New(nil, Config{SubjectTypes: []string{"pairwise"}})
	cfg := newDiscoveryCfg()

	p.Contribute(context.Background(), cfg)

	assert.Equal(t, []string{"pairwise"}, cfg.SubjectTypesSupported)
}

func TestContribute_StaticFields(t *testing.T) {
	p := New(nil)
	cfg := newDiscoveryCfg()

	p.Contribute(context.Background(), cfg)

	assert.Equal(t, []string{"normal"}, cfg.ClaimTypesSupported)
	assert.True(t, cfg.ClaimsParameterSupported)
	assert.True(t, cfg.RequestParameterSupported)
	assert.True(t, cfg.RequestURIParameterSupported)
	assert.False(t, cfg.RequireRequestURIRegistration)
	assert.True(t, cfg.AuthorizationResponseISSParameterSupported)
}

func TestContribute_ClaimsSupported(t *testing.T) {
	p := New(nil)
	cfg := newDiscoveryCfg()

	p.Contribute(context.Background(), cfg)

	assert.Contains(t, cfg.ClaimsSupported, "sub")
	assert.Contains(t, cfg.ClaimsSupported, "email")
	assert.Contains(t, cfg.ClaimsSupported, "phone_number")
	assert.Contains(t, cfg.ClaimsSupported, "address")
	assert.Contains(t, cfg.ClaimsSupported, "preferred_username")
}

func TestContribute_ExtraFields(t *testing.T) {
	p := New(nil, Config{
		ExtraFields: map[string]any{
			"custom_bool":   true,
			"custom_string": "hello",
		},
	})
	cfg := newDiscoveryCfg()

	p.Contribute(context.Background(), cfg)

	assert.Equal(t, true, cfg.Extra["custom_bool"])
	assert.Equal(t, "hello", cfg.Extra["custom_string"])
}

func TestContribute_ExtraFields_Nil(t *testing.T) {
	p := New(nil)
	cfg := newDiscoveryCfg()

	p.Contribute(context.Background(), cfg)

	// Extra should not be nil (initialized by caller), and no panic
	assert.NotNil(t, cfg.Extra)
}

func TestRegister_IsNoOp(t *testing.T) {
	p := New(nil)
	// Register should not panic with nil router (it's a no-op)
	assert.NotPanics(t, func() {
		p.Register(nil)
	})
}
