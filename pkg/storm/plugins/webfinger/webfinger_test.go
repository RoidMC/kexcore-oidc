// Package webfinger — tests for RFC 7033 WebFinger endpoint.
//
// References:
//   - RFC 7033: https://www.rfc-editor.org/rfc/rfc7033
//   - OIDC Discovery 1.0 §2: Issuer Discovery via WebFinger
package webfinger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// --- helpers ---

func newRouter(issuer string) *chi.Mux {
	p := NewWithConfig()
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := shared.ContextWithIssuer(r.Context(), issuer)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	p.Register(r)
	return r
}

func doGet(t *testing.T, router *chi.Mux, url string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

// --- RFC 7033 §4.2: Performing a WebFinger Request ---

// RFC 7033 §4.2: The "resource" query parameter is REQUIRED.
// If missing, the server MUST return 400.
func TestWebFinger_MissingResource_Returns400(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "resource parameter required")
}

// RFC 7033 §4.2: The resource parameter must be a valid URI.
// An unsupported scheme (e.g., "mailto:") returns 400.
func TestWebFinger_UnsupportedScheme_Returns400(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=mailto:user@example.com")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unsupported resource scheme")
}

// RFC 7033 §4.4: Successful response with acct: URI.
// The response MUST be JRD (JSON Resource Descriptor) format.
func TestWebFinger_AcctURI_Success(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com")

	require.Equal(t, http.StatusOK, w.Code)

	// Content-Type MUST be application/jrd+json (RFC 7033 §4.4)
	assert.Equal(t, "application/jrd+json", w.Header().Get("Content-Type"))

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// RFC 7033 §4.4.1: "subject" MUST match the request resource
	assert.Equal(t, "acct:user@op.example.com", resp.Subject)

	// OIDC Discovery §2: The response MUST contain an issuer link
	require.Len(t, resp.Links, 1)
	assert.Equal(t, "http://openid.net/specs/connect/1.0/issuer", resp.Links[0].Rel)
	assert.Equal(t, "https://op.example.com", resp.Links[0].Href)
}

// RFC 7033 §4.2: The resource parameter can also be an https: URI.
func TestWebFinger_HTTPSResource_Success(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=https://op.example.com/user")

	require.Equal(t, http.StatusOK, w.Code)

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Equal(t, "https://op.example.com/user", resp.Subject)
	require.Len(t, resp.Links, 1)
	assert.Equal(t, "https://op.example.com", resp.Links[0].Href)
}

// RFC 7033 §4.4.2: If the resource host doesn't match the issuer host,
// the server SHOULD return 404.
func TestWebFinger_HostMismatch_Returns404(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@other-domain.com")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// RFC 7033 §5: CORS is handled by the engine's middleware layer (rs/cors),
// not by the plugin itself. This is tested at the integration level.

// OIDC Discovery §2: Issuer discovery with case-insensitive host matching.
func TestWebFinger_CaseInsensitiveHost_Matches(t *testing.T) {
	r := newRouter("https://OP.EXAMPLE.COM")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com")

	assert.Equal(t, http.StatusOK, w.Code)
}

// RFC 7033 §4.2: The resource parameter is REQUIRED — empty value returns 400.
func TestWebFinger_EmptyResource_Returns400(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=")

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// RFC 7033 §4.4.1: The "subject" field in the response MUST be present.
func TestWebFinger_SubjectPresent(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:alice@op.example.com")

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Subject)
}

// RFC 7033 §4.4: The link relation type for OIDC issuer discovery is
// "http://openid.net/specs/connect/1.0/issuer".
func TestWebFinger_LinkRelationType_Correct(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com")

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	require.Len(t, resp.Links, 1)
	assert.Equal(t, "http://openid.net/specs/connect/1.0/issuer", resp.Links[0].Rel)
}

// OIDC Discovery §2: The issuer URL in the response MUST be the OP's issuer identifier.
func TestWebFinger_IssuerURL_MatchesOP(t *testing.T) {
	issuer := "https://auth.example.com/"
	r := newRouter(issuer)
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@auth.example.com")

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	require.Len(t, resp.Links, 1)
	assert.Equal(t, issuer, resp.Links[0].Href)
}

// --- extractHost unit tests ---

func TestExtractHost_AcctURI(t *testing.T) {
	assert.Equal(t, "example.com", extractHost("acct:user@example.com"))
	assert.Equal(t, "op.example.com", extractHost("acct:alice@op.example.com"))
}

func TestExtractHost_HTTPSURI(t *testing.T) {
	assert.Equal(t, "example.com", extractHost("https://example.com"))
	assert.Equal(t, "example.com", extractHost("https://example.com/"))
	assert.Equal(t, "example.com", extractHost("https://example.com/path"))
	assert.Equal(t, "example.com", extractHost("https://example.com/path?q=1"))
}

func TestExtractHost_InvalidAcct(t *testing.T) {
	assert.Equal(t, "", extractHost("acct:userwithoutat"))
}

func TestExtractHost_Empty(t *testing.T) {
	assert.Equal(t, "", extractHost(""))
}

// --- RFC 7033 §4.3: The "rel" Parameter ---

// RFC 7033 §4.3: When the "rel" parameter is present, the server MUST
// return only links matching the requested relation types.
func TestWebFinger_RelParameter_FiltersLinks(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com&rel=http://openid.net/specs/connect/1.0/issuer")

	require.Equal(t, http.StatusOK, w.Code)

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// The requested rel matches our link, so it should be present
	require.Len(t, resp.Links, 1)
	assert.Equal(t, "http://openid.net/specs/connect/1.0/issuer", resp.Links[0].Rel)
}

// RFC 7033 §4.3: If the "rel" parameter requests a relation type that
// does not exist, the "links" array MUST be empty.
func TestWebFinger_RelParameter_NonMatching_ReturnsEmptyLinks(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com&rel=http://nonexistent.example.com/rel")

	require.Equal(t, http.StatusOK, w.Code)

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// Non-matching rel → empty links
	assert.Empty(t, resp.Links)
}

// RFC 7033 §4.3: The "rel" parameter can appear multiple times.
// The server MUST include links matching ANY of the requested rel types.
func TestWebFinger_MultipleRelParameters(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com&rel=http://openid.net/specs/connect/1.0/issuer&rel=http://nonexistent.example.com/rel")

	require.Equal(t, http.StatusOK, w.Code)

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// One matches, one doesn't → should have 1 link
	require.Len(t, resp.Links, 1)
	assert.Equal(t, "http://openid.net/specs/connect/1.0/issuer", resp.Links[0].Rel)
}

// RFC 7033 §4.3: Even when "rel" is present, the subject and other
// fields MUST still be returned.
func TestWebFinger_RelParameter_SubjectStillPresent(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com&rel=http://openid.net/specs/connect/1.0/issuer")

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// RFC 7033 §4.3: "other name/value pairs in the response, including
	// any aliases or properties, would be returned"
	assert.Equal(t, "acct:user@op.example.com", resp.Subject)
}

// RFC 7033 §4.3: When "rel" is absent, all links MUST be returned.
func TestWebFinger_NoRelParameter_ReturnsAllLinks(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com")

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// No rel parameter → all links returned
	require.Len(t, resp.Links, 1)
	assert.Equal(t, "http://openid.net/specs/connect/1.0/issuer", resp.Links[0].Rel)
}

// --- RFC 7033 §4.4: JRD Content-Type ---

// RFC 7033 §10.2: The media type for JRD is application/jrd+json.
func TestWebFinger_ContentType_JRD(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com")

	assert.Equal(t, "application/jrd+json", w.Header().Get("Content-Type"))
}

// RFC 7033 §4.4: Error responses MUST also use JRD content type.
func TestWebFinger_ErrorResponses_UseJRDContentType(t *testing.T) {
	r := newRouter("https://op.example.com")

	// Missing resource → 400 with JRD content type
	w := doGet(t, r, "/.well-known/webfinger")
	assert.Equal(t, "application/jrd+json", w.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Unsupported scheme → 400 with JRD content type
	w = doGet(t, r, "/.well-known/webfinger?resource=mailto:user@example.com")
	assert.Equal(t, "application/jrd+json", w.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Host mismatch → 404 with JRD content type
	w = doGet(t, r, "/.well-known/webfinger?resource=acct:user@other.com")
	assert.Equal(t, "application/jrd+json", w.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- RFC 7033 §4.4.4: Links ---

// RFC 7033 §4.4.4.1: Each link MUST have a "rel" member.
func TestWebFinger_Link_HasRelField(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com")

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	for _, l := range resp.Links {
		assert.NotEmpty(t, l.Rel, "link must have a rel field")
	}
}

// RFC 7033 §4.4.4.3: Each link MUST have an "href" member.
func TestWebFinger_Link_HasHrefField(t *testing.T) {
	r := newRouter("https://op.example.com")
	w := doGet(t, r, "/.well-known/webfinger?resource=acct:user@op.example.com")

	var resp webFingerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	for _, l := range resp.Links {
		assert.NotEmpty(t, l.Href, "link must have an href field")
	}
}

// --- Plugin interface tests ---

func TestPlugin_Name(t *testing.T) {
	p := NewWithConfig()
	assert.Equal(t, "webfinger", p.Name())
}
