// Package keys — tests for JWKS endpoint plugin.
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

var errKeyNotFound = errors.New("keys not found")

// --- fakes ---

type fakeKey struct {
	id    string
	alg   string
	use   string
	key   jwk.Key
	certs [][]byte // optional certificate chain
}

func (k *fakeKey) ID() string        { return k.id }
func (k *fakeKey) Algorithm() string { return k.alg }
func (k *fakeKey) Use() string       { return k.use }
func (k *fakeKey) Key() jwk.Key      { return k.key }

// CertificateProvider implementation
func (k *fakeKey) CertificateChain() ([][]byte, error) {
	return k.certs, nil
}

type fakeKeyStore struct {
	keys   []protocol.Key
	keyErr error
	key    storm.SigningKey
}

func (s *fakeKeyStore) KeySet(ctx context.Context) ([]protocol.Key, error) {
	if s.keyErr != nil {
		return nil, s.keyErr
	}
	return s.keys, nil
}

func (s *fakeKeyStore) SignatureAlgorithms(ctx context.Context) ([]string, error) {
	return []string{"ES256"}, nil
}

func (s *fakeKeyStore) SigningKey(ctx context.Context) (storm.SigningKey, error) {
	if s.key != nil {
		return s.key, nil
	}
	return nil, errKeyNotFound
}

var _ storm.KeyStore = (*fakeKeyStore)(nil)

// --- helpers ---

func generateECDSAKey(t *testing.T) jwk.Key {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import[jwk.Key](privKey.Public())
	require.NoError(t, err)
	return key
}

// --- Storage interface implementation for fakeKeyStore ---

func (s *fakeKeyStore) GetClientByClientID(ctx context.Context, clientID string) (storm.Client, error) {
	return nil, errKeyNotFound
}
func (s *fakeKeyStore) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	return errKeyNotFound
}
func (s *fakeKeyStore) Health(ctx context.Context) error { return nil }

var _ storm.Storage = (*fakeKeyStore)(nil)

func newTestPlugin(store storm.KeyStore) *Plugin {
	return NewWithStore(store)
}

// --- Tests ---

// JWKS returns keys in standard format.
func TestKeys_ReturnsKeys(t *testing.T) {
	ecKey := generateECDSAKey(t)
	store := &fakeKeyStore{
		keys: []protocol.Key{
			&fakeKey{id: "key-1", alg: "ES256", use: "sig", key: ecKey},
		},
	}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	ctx := shared.ContextWithIssuer(r.Context(), "https://op.example.com")
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	p.handle(w, r)

	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Keys, 1)
}

// Empty key set returns empty array.
func TestKeys_EmptyKeySet(t *testing.T) {
	store := &fakeKeyStore{keys: []protocol.Key{}}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	ctx := shared.ContextWithIssuer(r.Context(), "https://op.example.com")
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	p.handle(w, r)

	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Keys, 0)
}

// Store error returns 500.
func TestKeys_StoreError(t *testing.T) {
	store := &fakeKeyStore{keyErr: errKeyNotFound}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	ctx := shared.ContextWithIssuer(r.Context(), "https://op.example.com")
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	p.handle(w, r)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// Multiple keys returned correctly.
func TestKeys_MultipleKeys(t *testing.T) {
	ecKey1 := generateECDSAKey(t)
	ecKey2 := generateECDSAKey(t)
	store := &fakeKeyStore{
		keys: []protocol.Key{
			&fakeKey{id: "key-1", alg: "ES256", use: "sig", key: ecKey1},
			&fakeKey{id: "key-2", alg: "ES256", use: "enc", key: ecKey2},
		},
	}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	ctx := shared.ContextWithIssuer(r.Context(), "https://op.example.com")
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	p.handle(w, r)

	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Keys, 2)
}

// Nil key is skipped.
func TestKeys_NilKeySkipped(t *testing.T) {
	ecKey := generateECDSAKey(t)
	store := &fakeKeyStore{
		keys: []protocol.Key{
			&fakeKey{id: "key-1", alg: "ES256", use: "sig", key: ecKey},
			&fakeKey{id: "key-nil", alg: "ES256", use: "sig", key: nil},
		},
	}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	ctx := shared.ContextWithIssuer(r.Context(), "https://op.example.com")
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	p.handle(w, r)

	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Keys, 1) // nil key skipped
}

// Discovery contributes jwks_uri.
func TestKeys_Discovery(t *testing.T) {
	p := newTestPlugin(&fakeKeyStore{})
	cfg := &protocol.DiscoveryConfiguration{}
	p.Contribute(context.Background(), cfg)

	assert.NotEmpty(t, cfg.JWKSURI)
	assert.Contains(t, cfg.JWKSURI, "/.well-known/jwks.json")
}

// init() factory works with valid KeyStore.
func TestKeys_InitFactory(t *testing.T) {
	factory := getKeysFactory()
	require.NotNil(t, factory)

	ctx := &storm.PluginContext{
		Storage: &fakeKeyStore{keys: []protocol.Key{}},
	}
	plugin := factory(ctx)
	assert.NotNil(t, plugin)
	assert.Equal(t, "keys", plugin.Name())
}

// --- helpers for init() test ---

func getKeysFactory() storm.PluginFactory {
	return func(ctx *storm.PluginContext) storm.Plugin {
		return New(ctx)
	}
}

// Name returns "keys".
func TestKeys_Name(t *testing.T) {
	p := newTestPlugin(&fakeKeyStore{})
	assert.Equal(t, "keys", p.Name())
}

// Category returns CategoryCore.
func TestKeys_Category(t *testing.T) {
	p := newTestPlugin(&fakeKeyStore{})
	assert.Equal(t, storm.CategoryCore, p.Category())
}

// Requires returns KeyStore dependency.
func TestKeys_Requires(t *testing.T) {
	p := newTestPlugin(&fakeKeyStore{})
	requires := p.Requires()
	assert.Contains(t, requires, "KeyStore")
}

// Register installs the JWKS route.
func TestKeys_Route(t *testing.T) {
	p := newTestPlugin(&fakeKeyStore{})
	assert.Equal(t, "keys", p.Name())
}

// Response is valid JSON with keys array.
func TestKeys_ValidJSONResponse(t *testing.T) {
	ecKey := generateECDSAKey(t)
	store := &fakeKeyStore{
		keys: []protocol.Key{
			&fakeKey{id: "key-1", alg: "ES256", use: "sig", key: ecKey},
		},
	}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	ctx := shared.ContextWithIssuer(r.Context(), "https://op.example.com")
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	p.handle(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, json.Valid(w.Body.Bytes()))

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	assert.Contains(t, raw, "keys")
}

// Private key JWK must preserve use/kid/alg after PublicKey() extraction.
// This is the root cause of oidcc-server-rotate-keys failure:
// jwx PublicKey() drops non-intrinsic fields, so JWKS lacked "use":"sig".
func TestKeys_PrivateKeyPreservesUseField(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Import the PRIVATE key (like storage.signingKey.Key() does)
	jwkKey, err := jwk.Import[jwk.Key](privKey)
	require.NoError(t, err)
	_ = jwkKey.Set(jwk.KeyIDKey, "test-kid")
	_ = jwkKey.Set(jwk.AlgorithmKey, "ES256")
	_ = jwkKey.Set(jwk.KeyUsageKey, "sig")

	store := &fakeKeyStore{
		keys: []protocol.Key{
			&fakeKey{id: "test-kid", alg: "ES256", use: "sig", key: jwkKey},
		},
	}
	p := newTestPlugin(store)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	ctx := shared.ContextWithIssuer(r.Context(), "https://op.example.com")
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	p.handle(w, r)

	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Keys, 1)

	key := resp.Keys[0]
	assert.Equal(t, "sig", key["use"], "JWKS must include use:sig after PublicKey() extraction")
	assert.Equal(t, "test-kid", key["kid"], "JWKS must preserve kid after PublicKey() extraction")
	assert.Equal(t, "ES256", key["alg"], "JWKS must preserve alg after PublicKey() extraction")
}
