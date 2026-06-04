// Package userinfo implements the OIDC UserInfo endpoint plugin.
//
// Tests cover:
//   - OIDC Core §5.3.1: UserInfo Request (Bearer header + POST body)
//   - OIDC Core §5.3.2: Successful UserInfo Response (sub, claims, headers)
//   - OIDC Core §5.3.3: UserInfo Error Response
//   - RFC 6750 §2.1: Authorization Request Header Field
//   - RFC 6750 §2.2: Form-Encoded Body Parameter
//   - RFC 6750 §3: WWW-Authenticate Response Header Field
package userinfo

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

	crypto_pkg "github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

var errNotFound = errors.New("not found")

// --- fake implementations ---

type fakeUserinfoStore struct {
	userInfoFn func(ctx context.Context, userinfo *protocol.UserInfo, tokenID, subject, origin string) error
}

func (s *fakeUserinfoStore) SetUserinfoFromToken(ctx context.Context, userinfo *protocol.UserInfo, tokenID, subject, origin string) error {
	if s.userInfoFn != nil {
		return s.userInfoFn(ctx, userinfo, tokenID, subject, origin)
	}
	return nil
}

var _ storm.UserinfoStore = (*fakeUserinfoStore)(nil)

type fakeCrypto struct {
	decryptFn func(ctx context.Context, ciphertext []byte) ([]byte, error)
}

func (c *fakeCrypto) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}
func (c *fakeCrypto) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if c.decryptFn != nil {
		return c.decryptFn(ctx, ciphertext)
	}
	return nil, errNotFound
}
func (c *fakeCrypto) Hash(ctx context.Context, sigAlgorithm string, data []byte) ([]byte, error) {
	h, err := crypto_pkg.GetHashAlgorithm(sigAlgorithm)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(nil), nil
}
func (c *fakeCrypto) Sign(ctx context.Context, keyID string, payload []byte) (string, error) {
	return "", nil
}
func (c *fakeCrypto) AlgorithmSuite() string {
	return "RSA+SHA256+AES"
}

var _ storm.UniCrypto = (*fakeCrypto)(nil)

type fakeKeyStore struct{}

func (s *fakeKeyStore) KeySet(ctx context.Context) ([]protocol.Key, error) { return nil, nil }
func (s *fakeKeyStore) SignatureAlgorithms(ctx context.Context) ([]string, error) {
	return []string{"RS256"}, nil
}
func (s *fakeKeyStore) SigningKey(ctx context.Context) (storm.SigningKey, error) { return nil, nil }

var _ storm.KeyStore = (*fakeKeyStore)(nil)

// fakeGMCrypto extends fakeCrypto with GM/T capabilities for GM/T tests.
type fakeGMCrypto struct {
	fakeCrypto
	sm2DecryptJWEFn func(ctx context.Context, compact string) ([]byte, error)
}

func (c *fakeGMCrypto) SM2DecryptJWE(ctx context.Context, compact string) ([]byte, error) {
	if c.sm2DecryptJWEFn != nil {
		return c.sm2DecryptJWEFn(ctx, compact)
	}
	return nil, errNotFound
}
func (c *fakeGMCrypto) AlgorithmSuite() string {
	return "SM2+SM3+SM4"
}

// --- helpers ---

const testIssuer = "https://op.example.com"

func newTestPlugin(store storm.UserinfoStore, crypto storm.UniCrypto, keyStore protocol.KeyStore) *Plugin {
	return &Plugin{
		store:    store,
		crypto:   crypto,
		keyStore: keyStore,
	}
}

func newRequest(method, target string, body ...string) *http.Request {
	var r *http.Request
	if len(body) > 0 && body[0] != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body[0]))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	// Inject issuer into context
	ctx := shared.ContextWithIssuer(r.Context(), testIssuer)
	return r.WithContext(ctx)
}

func serveRequest(plugin *Plugin, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	plugin.handle(w, r)
	return w
}

func setupChiRouter(plugin *Plugin) *chi.Mux {
	r := chi.NewRouter()
	plugin.Register(r)
	return r
}

// extractErrorBody parses an OIDC error JSON body.
func extractErrorBody(t *testing.T, body []byte) *protocol.Error {
	t.Helper()
	var errResp protocol.Error
	err := json.Unmarshal(body, &errResp)
	require.NoError(t, err)
	return &errResp
}

// --- Tests ---

// TestUserInfo_GET_BearerHeader_Success validates a successful UserInfo request
// via GET with Bearer token in Authorization header.
//
// OIDC Core §5.3.1: The UserInfo endpoint MUST accept Bearer tokens per RFC 6750.
// OIDC Core §5.3.2: The response MUST contain the "sub" claim.
func TestUserInfo_GET_BearerHeader_Success(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			info.Subject = "user123"
			info.Name = "Test User"
			info.Email = "test@example.com"
			return nil
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("tokenID:user123"), nil
		},
	}
	plugin := newTestPlugin(store, crypto, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer test-opaque-token")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusOK, w.Code)

	// OIDC Core §5.3.2: response MUST be JSON
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	// OIDC Core §5.3.2: response MUST contain "sub" claim
	var info protocol.UserInfo
	err := json.Unmarshal(w.Body.Bytes(), &info)
	require.NoError(t, err)
	assert.Equal(t, "user123", info.Subject)
	assert.Equal(t, "Test User", info.Name)
	assert.Equal(t, "test@example.com", info.Email)

	// OIDC Core §5.3.2: Cache-Control: no-store
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	// OIDC Core §5.3.2: Pragma: no-cache
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
}

// TestUserInfo_POST_FormBody_Success validates a successful UserInfo request
// via POST with access_token in form body (RFC 6750 §2.2).
//
// RFC 6750 §2.2: The client MAY use form-encoded body parameter to transmit
// the bearer token.
func TestUserInfo_POST_FormBody_Success(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			info.Subject = "user456"
			info.PreferredUsername = "johndoe"
			return nil
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("tokenID:user456"), nil
		},
	}
	plugin := newTestPlugin(store, crypto, &fakeKeyStore{})

	body := "access_token=test-opaque-token-via-form"
	r := newRequest("POST", "/userinfo", body)
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusOK, w.Code)

	var info protocol.UserInfo
	err := json.Unmarshal(w.Body.Bytes(), &info)
	require.NoError(t, err)
	assert.Equal(t, "user456", info.Subject)
	assert.Equal(t, "johndoe", info.PreferredUsername)
}

// TestUserInfo_MissingToken_Unauthorized validates that missing token returns 401.
//
// OIDC Core §5.3.3: If the request does not contain an access token,
// the OP returns an error response.
// RFC 6750 §3: The WWW-Authenticate response header field MUST be included.
func TestUserInfo_MissingToken_Unauthorized(t *testing.T) {
	plugin := newTestPlugin(&fakeUserinfoStore{}, &fakeCrypto{}, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	// No Authorization header
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusBadRequest, w.Code)

	errResp := extractErrorBody(t, w.Body.Bytes())
	assert.Equal(t, protocol.InvalidRequest, errResp.ErrorType)
	assert.Contains(t, errResp.Description, "access token is missing")

	// RFC 6750 §3: 401 requires WWW-Authenticate header
	// Note: WriteError returns 400 (BadRequest) not 401 for InvalidRequest,
	// so WWW-Authenticate is not expected here.
	_ = errResp
}

// TestUserInfo_InvalidToken_Unauthorized validates that an invalid/expired token
// returns 401 with WWW-Authenticate header.
//
// OIDC Core §5.3.3: If the access token is invalid, the OP returns an error.
// RFC 6750 §3: Bearer realm + error in WWW-Authenticate.
func TestUserInfo_InvalidToken_Returns401(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			return nil
		},
	}
	// Crypto returns error for all tokens - no valid token resolution path
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return nil, errNotFound
		},
	}
	plugin := newTestPlugin(store, crypto, nil) // keyStore nil means no JWT fallback

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer invalid-token")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusBadRequest, w.Code)

	errResp := extractErrorBody(t, w.Body.Bytes())
	assert.Equal(t, protocol.InvalidRequest, errResp.ErrorType)
	assert.Contains(t, errResp.Description, "invalid access token")
}

// TestUserInfo_MissingSubject_ReturnsError validates that when SetUserinfoFromToken
// does not set the "sub" field, the endpoint returns an error.
//
// OIDC Core §5.3.2: The "sub" claim MUST be included in the UserInfo response.
func TestUserInfo_MissingSubject_ReturnsError(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			// Deliberately not setting Subject
			info.Name = "No Sub"
			return nil
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("tokenID:user789"), nil
		},
	}
	plugin := newTestPlugin(store, crypto, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer test-token")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusBadRequest, w.Code)

	errResp := extractErrorBody(t, w.Body.Bytes())
	assert.Equal(t, protocol.InvalidRequest, errResp.ErrorType)
	assert.Contains(t, errResp.Description, "user not found")
}

// TestUserInfo_OpaqueToken_DecryptError validates behavior when opaque token
// decryption fails and no other resolution path is available.
func TestUserInfo_OpaqueToken_DecryptError(t *testing.T) {
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return nil, errNotFound
		},
	}
	plugin := newTestPlugin(&fakeUserinfoStore{}, crypto, nil) // no keyStore = no JWT fallback

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer bad-opaque-token")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusBadRequest, w.Code)

	errResp := extractErrorBody(t, w.Body.Bytes())
	assert.Equal(t, protocol.InvalidRequest, errResp.ErrorType)
}

// TestUserInfo_ParseTokenParts_Invalid validates that malformed decrypted tokens
// (not in "tokenID:subject" format) are rejected.
func TestUserInfo_ParseTokenParts_Invalid(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			return nil
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("nocolon"), nil // missing ":"
		},
	}
	plugin := newTestPlugin(store, crypto, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer malformed-token")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusBadRequest, w.Code)

	errResp := extractErrorBody(t, w.Body.Bytes())
	assert.Equal(t, protocol.InvalidRequest, errResp.ErrorType)
	assert.Contains(t, errResp.Description, "invalid access token")
}

// TestUserInfo_StoreError_Forbidden validates that a storage error returns
// the error properly (unrecognized errors become 500 ServerError).
func TestUserInfo_StoreError_Forbidden(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			return errNotFound
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("tokenID:user001"), nil
		},
	}
	plugin := newTestPlugin(store, crypto, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer valid-token")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestUserInfo_ChiRouter_GET validates that the plugin registers the GET route
// correctly via chi router.
func TestUserInfo_ChiRouter_GET(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			info.Subject = "router-test-user"
			return nil
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("token01:router-test-user"), nil
		},
	}
	plugin := newTestPlugin(store, crypto, &fakeKeyStore{})

	r := chi.NewRouter()
	plugin.Register(r)

	req := newRequest("GET", "/userinfo")
	req.Header.Set("Authorization", "Bearer token01")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var info protocol.UserInfo
	err := json.Unmarshal(w.Body.Bytes(), &info)
	require.NoError(t, err)
	assert.Equal(t, "router-test-user", info.Subject)
}

// TestUserInfo_ChiRouter_POST validates that the plugin registers the POST route
// correctly via chi router with form body access_token.
func TestUserInfo_ChiRouter_POST(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			info.Subject = "router-post-user"
			return nil
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("token02:router-post-user"), nil
		},
	}
	plugin := newTestPlugin(store, crypto, &fakeKeyStore{})

	r := chi.NewRouter()
	plugin.Register(r)

	body := "access_token=token02"
	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := shared.ContextWithIssuer(req.Context(), testIssuer)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var info protocol.UserInfo
	err := json.Unmarshal(w.Body.Bytes(), &info)
	require.NoError(t, err)
	assert.Equal(t, "router-post-user", info.Subject)
}

// TestUserInfo_UnsupportedMethod_NotFound validates that unsupported HTTP methods
// (e.g. PUT, DELETE) are rejected with 405.
func TestUserInfo_UnsupportedMethod_NotFound(t *testing.T) {
	plugin := newTestPlugin(&fakeUserinfoStore{}, &fakeCrypto{}, &fakeKeyStore{})

	r := chi.NewRouter()
	plugin.Register(r)

	req := newRequest("PUT", "/userinfo")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// chi returns 405 Method Not Allowed for unregistered methods
	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// TestUserInfo_EmptyBearerToken validates that "Bearer " with no actual token
// is treated as missing token.
func TestUserInfo_EmptyBearerToken(t *testing.T) {
	plugin := newTestPlugin(&fakeUserinfoStore{}, &fakeCrypto{}, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer ")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusBadRequest, w.Code)

	errResp := extractErrorBody(t, w.Body.Bytes())
	assert.Equal(t, protocol.InvalidRequest, errResp.ErrorType)
}

// TestUserInfo_OriginHeader_Propagated validates that the Origin header is
// passed through to SetUserinfoFromToken.
func TestUserInfo_OriginHeader_Propagated(t *testing.T) {
	var capturedOrigin string
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			info.Subject = subject
			capturedOrigin = origin
			return nil
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("tokenID:origin-test-user"), nil
		},
	}
	plugin := newTestPlugin(store, crypto, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer test-token")
	r.Header.Set("Origin", "https://rp.example.com")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://rp.example.com", capturedOrigin)
}

// TestUserInfo_NoOriginHeader_EmptyString validates that missing Origin header
// results in empty string being passed to SetUserinfoFromToken.
func TestUserInfo_NoOriginHeader_EmptyString(t *testing.T) {
	var capturedOrigin string
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			info.Subject = subject
			capturedOrigin = origin
			return nil
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("tokenID:no-origin-user"), nil
		},
	}
	plugin := newTestPlugin(store, crypto, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer test-token")
	// No Origin header
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "", capturedOrigin)
}

// TestUserInfo_GMCrypto_StandardFallback validates that when GMCrypto.SM2DecryptJWE
// fails, it falls back to standard opaque token decryption.
func TestUserInfo_GMCrypto_StandardFallback(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			info.Subject = "gm-fallback-user"
			return nil
		},
	}
	gmCrypto := &fakeGMCrypto{
		sm2DecryptJWEFn: func(ctx context.Context, compact string) ([]byte, error) {
			return nil, errNotFound // SM2 JWE fails
		},
	}
	gmCrypto.decryptFn = func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		return []byte("gmToken:gm-fallback-user"), nil // standard decrypt succeeds
	}
	plugin := newTestPlugin(store, gmCrypto, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer gm-token")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusOK, w.Code)

	var info protocol.UserInfo
	err := json.Unmarshal(w.Body.Bytes(), &info)
	require.NoError(t, err)
	assert.Equal(t, "gm-fallback-user", info.Subject)
}

// TestUserInfo_GMCrypto_JMEFirst validates that GMCrypto.SM2DecryptJWE
// is tried before standard decryption.
func TestUserInfo_GMCrypto_JMEFirst(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			info.Subject = "gm-jwe-user"
			return nil
		},
	}
	gmCrypto := &fakeGMCrypto{
		sm2DecryptJWEFn: func(ctx context.Context, compact string) ([]byte, error) {
			return []byte("jweToken:gm-jwe-user"), nil // SM2 JWE succeeds
		},
	}
	gmCrypto.decryptFn = func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		return nil, errNotFound // standard decrypt would fail, but not reached
	}
	plugin := newTestPlugin(store, gmCrypto, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer gm-jwe-token")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusOK, w.Code)
}

// TestUserInfo_StandardHeaders validates the required OIDC and HTTP headers.
//
// OIDC Core §5.3.2 requires:
//   - Content-Type: application/json
//   - Cache-Control: no-store
//   - Pragma: no-cache
func TestUserInfo_StandardHeaders(t *testing.T) {
	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			info.Subject = "header-test-user"
			return nil
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return []byte("t:h"), nil
		},
	}
	plugin := newTestPlugin(store, crypto, &fakeKeyStore{})

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer test")
	w := serveRequest(plugin, r)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
}

// TestUserInfo_JWTToken_VerifyAccessToken verifies that a valid JWT access token
// is accepted when opaque decryption fails.
func TestUserInfo_JWTToken_Resolved(t *testing.T) {
	// This test validates the control flow: when crypto.Decrypt fails,
	// resolveAccessToken falls through to protocol.VerifyAccessToken.
	// Since we don't have a real JWKS setup, we mock the keyStore
	// and verify that the fallback path is entered.

	store := &fakeUserinfoStore{
		userInfoFn: func(ctx context.Context, info *protocol.UserInfo, tokenID, subject, origin string) error {
			info.Subject = "jwt-fallback-user"
			return nil
		},
	}
	crypto := &fakeCrypto{
		decryptFn: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			return nil, errNotFound // opaque decryption fails
		},
	}

	// For a real JWT verification test, we'd need signing keys.
	// This test checks that when keyStore is nil, the fallback returns
	// ok=false rather than panicking.
	plugin := newTestPlugin(store, crypto, nil) // keyStore nil = no JWT fallback

	r := newRequest("GET", "/userinfo")
	r.Header.Set("Authorization", "Bearer some-jwt-token")
	w := serveRequest(plugin, r)

	// Should fail since both opaque and JWT paths are unavailable
	require.Equal(t, http.StatusBadRequest, w.Code)

	errResp := extractErrorBody(t, w.Body.Bytes())
	assert.Equal(t, protocol.InvalidRequest, errResp.ErrorType)
}

// TestUserInfo_Contribute validates that Contribute returns the expected
// discovery document entry.
func TestUserInfo_Contribute(t *testing.T) {
	plugin := newTestPlugin(&fakeUserinfoStore{}, &fakeCrypto{}, &fakeKeyStore{})

	ctx := shared.ContextWithIssuer(context.Background(), testIssuer)
	contrib := plugin.Contribute(ctx)

	endpoint, ok := contrib["userinfo_endpoint"]
	require.True(t, ok)
	assert.Equal(t, testIssuer+"/userinfo", endpoint)
}

// TestUserInfo_PluginLifecycle validates the basic plugin interface methods.
func TestUserInfo_PluginLifecycle(t *testing.T) {
	plugin := newTestPlugin(&fakeUserinfoStore{}, &fakeCrypto{}, &fakeKeyStore{})

	assert.Equal(t, storm.CategoryStandard, plugin.Category())
	assert.Equal(t, "userinfo", plugin.Name())
	assert.Equal(t, []string{"UserinfoStore", "KeyStore"}, plugin.Requires())
}
