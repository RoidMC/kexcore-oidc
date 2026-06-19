package jarm

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

// --- test helpers ---

type fakeSigningKey struct {
	alg string
	key jwk.Key
}

func (k *fakeSigningKey) ID() string        { return "test-key" }
func (k *fakeSigningKey) Algorithm() string { return k.alg }
func (k *fakeSigningKey) Key() jwk.Key      { return k.key }

type fakeKeyStore struct {
	signingKey *fakeSigningKey
}

func (s *fakeKeyStore) KeySet(ctx context.Context) ([]protocol.Key, error) {
	return nil, nil
}

func (s *fakeKeyStore) SigningKey(ctx context.Context) (storm.SigningKey, error) {
	return s.signingKey, nil
}

func (s *fakeKeyStore) SignatureAlgorithms(_ context.Context) ([]string, error) {
	return []string{s.signingKey.alg}, nil
}

// --- tests ---

func TestNew(t *testing.T) {
	key, _ := jwk.ParseKey([]byte(`{"kty":"RSA","n":"test","e":"AQAB"}`))
	ks := &fakeKeyStore{signingKey: &fakeSigningKey{alg: "RS256", key: key}}
	p := NewWithConfig(Config{
		KeyStore: ks,
		IssuerFn: shared.StaticIssuer("https://auth.example.com"),
	})

	if p.Name() != "jarm" {
		t.Errorf("Name() = %q, want %q", p.Name(), "jarm")
	}
	if p.Category() != storm.CategoryStandard {
		t.Errorf("Category() = %v, want %v", p.Category(), storm.CategoryStandard)
	}
}

func TestRequires(t *testing.T) {
	key, _ := jwk.ParseKey([]byte(`{"kty":"RSA","n":"test","e":"AQAB"}`))
	ks := &fakeKeyStore{signingKey: &fakeSigningKey{alg: "RS256", key: key}}
	p := NewWithConfig(Config{
		KeyStore: ks,
		IssuerFn: shared.StaticIssuer("https://auth.example.com"),
	})

	requires := p.Requires()
	if len(requires) != 1 || requires[0] != "KeyStore" {
		t.Errorf("Requires() = %v, want %v", requires, []string{"KeyStore"})
	}
}

func TestContribute(t *testing.T) {
	key, _ := jwk.ParseKey([]byte(`{"kty":"RSA","n":"test","e":"AQAB"}`))
	ks := &fakeKeyStore{signingKey: &fakeSigningKey{alg: "RS256", key: key}}
	p := NewWithConfig(Config{
		KeyStore: ks,
		IssuerFn: shared.StaticIssuer("https://auth.example.com"),
	})

	cfg := &protocol.DiscoveryConfiguration{
		ResponseModesSupported: []string{"query", "fragment", "form_post"},
	}

	p.Contribute(context.Background(), cfg)

	found := map[string]bool{
		"query.jwt":     false,
		"fragment.jwt":  false,
		"form_post.jwt": false,
	}
	for _, mode := range cfg.ResponseModesSupported {
		if _, ok := found[mode]; ok {
			found[mode] = true
		}
	}

	for mode, ok := range found {
		if !ok {
			t.Errorf("expected response mode %q in discovery", mode)
		}
	}
}

func TestResponseModeConstants(t *testing.T) {
	// Verify JARM response mode constants are defined
	if protocol.ResponseModeQueryJWT != "query.jwt" {
		t.Errorf("ResponseModeQueryJWT = %q, want %q", protocol.ResponseModeQueryJWT, "query.jwt")
	}
	if protocol.ResponseModeFragmentJWT != "fragment.jwt" {
		t.Errorf("ResponseModeFragmentJWT = %q, want %q", protocol.ResponseModeFragmentJWT, "fragment.jwt")
	}
	if protocol.ResponseModeFormPostJWT != "form_post.jwt" {
		t.Errorf("ResponseModeFormPostJWT = %q, want %q", protocol.ResponseModeFormPostJWT, "form_post.jwt")
	}
}
