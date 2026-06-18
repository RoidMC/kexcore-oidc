package shared

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// ClientStore is the minimal interface needed for client authentication.
//
// Security: AuthorizeClientIDSecret MUST use constant-time comparison
// (crypto/subtle.ConstantTimeCompare or bcrypt.CompareHashAndPassword)
// to prevent timing attacks that could reveal secret validity.
type ClientStore interface {
	GetClientByClientID(ctx context.Context, clientID string) (Client, error)
	AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error
}

// Client is the minimal client interface used by ClientAuthHelper.
type Client interface {
	GetID() string
	AuthMethod() protocol.AuthMethod
}

// JWKSProvider is optionally implemented by Client to provide
// the client's public JWKS keys for signature verification.
type JWKSProvider interface {
	ClientJWKS() []jwk.Key
}

// JWKSURIProvider is optionally implemented by Client to provide
// the client's jwks_uri for fetching fresh keys.
type JWKSURIProvider interface {
	ClientJWKSURI() string
}

// clientStoreFunc adapts function references to ClientStore.
// Used by NewClientAuthHelperFromFuncs to bridge stores with covariant return types.
type clientStoreFunc struct {
	getFn  func(ctx context.Context, clientID string) (Client, error)
	authFn func(ctx context.Context, clientID, clientSecret string) error
}

func (f *clientStoreFunc) GetClientByClientID(ctx context.Context, clientID string) (Client, error) {
	return f.getFn(ctx, clientID)
}

func (f *clientStoreFunc) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	return f.authFn(ctx, clientID, clientSecret)
}

// ClientAuthHelper extracts and verifies client credentials from HTTP requests.
// It supports Basic Auth, POST body, private_key_jwt (client_assertion),
// and tls_client_auth (mTLS certificate).
//
// Plugins that need client authentication can use this helper or implement
// their own logic for special cases (e.g., JWT Profile grants).
type ClientAuthHelper struct {
	store             ClientStore
	skipTLSCertVerify bool // skip TLS cert verification for JWKS fetches (testing only)
	allowPrivateIPs   bool // allow private IPs in JWKS URIs (testing only)
}

// NewClientAuthHelper creates a helper backed by the given store.
func NewClientAuthHelper(store ClientStore) *ClientAuthHelper {
	return &ClientAuthHelper{store: store}
}

// WithTLSSkipVerify enables skipping TLS certificate verification for JWKS fetches.
// Use ONLY for testing with self-signed certificates.
func (h *ClientAuthHelper) WithTLSSkipVerify(skip bool) *ClientAuthHelper {
	h.skipTLSCertVerify = skip
	return h
}

// WithAllowPrivateIPs allows private IPs in JWKS URIs.
// Use ONLY for testing/development environments.
func (h *ClientAuthHelper) WithAllowPrivateIPs(allow bool) *ClientAuthHelper {
	h.allowPrivateIPs = allow
	return h
}

// NewClientAuthHelperFromFuncs creates a helper backed by function references.
// Use this when bridging a store that returns clients with additional methods
// (e.g., storm.Client with LoginURL) — Go doesn't support covariant return types.
func NewClientAuthHelperFromFuncs(
	getFn func(ctx context.Context, clientID string) (Client, error),
	authFn func(ctx context.Context, clientID, clientSecret string) error,
) *ClientAuthHelper {
	return &ClientAuthHelper{store: &clientStoreFunc{getFn: getFn, authFn: authFn}}
}

// AuthenticateClient extracts client credentials from the request and
// verifies them against the store. Supports three authentication methods
// in order of precedence:
//  1. client_assertion (private_key_jwt) — RFC 7523 §2.2
//  2. mTLS certificate (tls_client_auth) — RFC 8705 §2
//  3. Basic Auth or form body (client_secret_basic / client_secret_post)
//
// Returns protocol.ErrInvalidClient if authentication fails.
func (h *ClientAuthHelper) AuthenticateClient(r *http.Request) (Client, error) {
	if err := r.ParseForm(); err != nil {
		return nil, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}

	// --- Method 1: client_assertion (private_key_jwt) ---
	if assertionType := r.Form.Get("client_assertion_type"); assertionType == protocol.ClientAssertionTypeJWTAssertion {
		assertion := r.Form.Get("client_assertion")
		if assertion == "" {
			return nil, protocol.ErrInvalidClient().WithDescription("client_assertion is missing")
		}
		getClient := func(ctx context.Context, cid string) (Client, error) {
			return h.store.GetClientByClientID(ctx, cid)
		}
		client, err := AuthenticatePrivateKeyJWT(r, getClient, assertion, nil, h.skipTLSCertVerify, h.allowPrivateIPs)
		if err != nil {
			return nil, protocol.ErrInvalidClient().WithParent(err)
		}
		return client, nil
	}

	clientID, clientSecret := r.Form.Get("client_id"), r.Form.Get("client_secret")

	// Basic auth takes precedence over form data.
	if id, secret, ok := r.BasicAuth(); ok {
		var err error
		clientID, err = url.QueryUnescape(id)
		if err != nil {
			return nil, protocol.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
		clientSecret, err = url.QueryUnescape(secret)
		if err != nil {
			return nil, protocol.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
	}

	if clientID == "" {
		return nil, protocol.ErrInvalidRequest().WithDescription("client_id missing")
	}

	client, err := h.store.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithParent(err)
	}

	// --- Method 2: tls_client_auth (mTLS certificate) ---
	if client.AuthMethod() == protocol.AuthMethodTLSClientAuth {
		cert := ClientCertFromContext(r.Context())
		if cert == nil {
			return nil, protocol.ErrInvalidClient().WithDescription("mTLS client certificate is required for tls_client_auth client")
		}
		// Optional: client-level certificate identity validation (RFC 8705 §2.1)
		if v, ok := client.(ClientCertBoundAuthenticator); ok {
			if err := v.ValidateClientCert(cert, clientID); err != nil {
				return nil, protocol.ErrInvalidClient().WithParent(err)
			}
		}
		return client, nil
	}

	// --- Method 3: Basic Auth / form body (client_secret_basic / client_secret_post) ---
	if client.AuthMethod() != protocol.AuthMethodNone {
		if err := h.store.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			return nil, err
		}
	}

	return client, nil
}

// ExtractBearerToken extracts a Bearer token from the Authorization header.
// Returns the token string, or empty string if not present or not a Bearer token.
func ExtractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// ParseClientCredentials extracts client credentials from the request
// without verifying them against the store.
// Returns protocol.ErrInvalidRequest if no credentials are found.
func ParseClientCredentials(r *http.Request) (clientID, clientSecret string, err error) {
	if err := r.ParseForm(); err != nil {
		return "", "", protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}

	clientID, clientSecret = r.Form.Get("client_id"), r.Form.Get("client_secret")

	if id, secret, ok := r.BasicAuth(); ok {
		var e error
		clientID, e = url.QueryUnescape(id)
		if e != nil {
			return "", "", protocol.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(e)
		}
		clientSecret, e = url.QueryUnescape(secret)
		if e != nil {
			return "", "", protocol.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(e)
		}
	}

	if clientID == "" {
		return "", "", protocol.ErrInvalidRequest().WithDescription("client_id missing")
	}

	return clientID, clientSecret, nil
}

// AuthenticatePrivateKeyJWT authenticates a client using a JWT assertion
// signed with the client's private key (RFC 7523 §2.2, OIDC Core §9).
//
// getClientByClientID is a function that looks up a client by ID.
// getAudiences is called after the client is resolved so the allowed aud
// values can depend on the client's profile (e.g. FAPI 2.0 vs plain OAuth).
// If nil, the assertion's audience is not checked (not recommended).
func AuthenticatePrivateKeyJWT(r *http.Request, getClientByClientID func(ctx context.Context, clientID string) (Client, error), assertion string, getAudiences func(client Client) []string, skipTLSVerify, allowPrivateIPs bool) (Client, error) {
	// Step 1: Parse the unverified JWT to extract iss (client_id).
	request := new(protocol.JWTTokenRequest)
	if _, err := protocol.ParseToken(assertion, request); err != nil {
		return nil, protocol.ErrInvalidClient().WithDescription("invalid client_assertion").WithParent(err)
	}
	if request.Issuer == "" {
		return nil, protocol.ErrInvalidClient().WithDescription("client_assertion missing iss claim")
	}

	// Step 2: Look up the client and verify it's configured for private_key_jwt.
	client, err := getClientByClientID(r.Context(), request.Issuer)
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithParent(err)
	}
	if client.AuthMethod() != protocol.AuthMethodPrivateKeyJWT {
		return nil, protocol.ErrInvalidClient().WithDescription("client not configured for private_key_jwt")
	}

	// Step 3: Get the client's keys for signature verification.
	clientKS, ok := client.(JWKSProvider)
	if !ok {
		return nil, protocol.ErrInvalidClient().WithDescription("client does not support private_key_jwt")
	}

	var clientKeys []jwk.Key
	if uriProvider, ok := client.(JWKSURIProvider); ok && uriProvider.ClientJWKSURI() != "" {
		slog.Info("AuthenticatePrivateKeyJWT: fetching jwks_uri",
			slog.String("client_id", request.Issuer),
			slog.String("jwks_uri", uriProvider.ClientJWKSURI()),
			slog.Int("static_keys", len(clientKS.ClientJWKS())),
			slog.Bool("skip_tls_verify", skipTLSVerify),
		)
		fetchedKeys, err := FetchJWKSFromURI(uriProvider.ClientJWKSURI(), skipTLSVerify, allowPrivateIPs)
		if err != nil {
			slog.Warn("AuthenticatePrivateKeyJWT: jwks_uri fetch failed, falling back to static keys",
				slog.String("client_id", request.Issuer),
				slog.String("jwks_uri", uriProvider.ClientJWKSURI()),
				slog.Any("error", err),
			)
			clientKeys = clientKS.ClientJWKS()
		} else {
			slog.Info("AuthenticatePrivateKeyJWT: jwks_uri fetched",
				slog.String("client_id", request.Issuer),
				slog.Int("fetched_keys", len(fetchedKeys)),
			)
			clientKeys = fetchedKeys
		}
	} else {
		clientKeys = clientKS.ClientJWKS()
	}

	if len(clientKeys) == 0 {
		return nil, protocol.ErrInvalidClient().WithDescription("client has no registered keys")
	}

	// Step 4: Determine allowed audiences based on client profile.
	var allowedAudiences []string
	if getAudiences != nil {
		allowedAudiences = getAudiences(client)
	}

	// Debug: log audience info
	slog.Info("[DEBUG] AuthenticatePrivateKeyJWT: audience check",
		"client_id", client.GetID(),
		"allowed_audiences", allowedAudiences,
	)

	// Step 5: Verify the assertion with the client's keys.
	if err := protocol.VerifyJWTAssertion(r.Context(), assertion, allowedAudiences, clientKeys, 10*time.Second); err != nil {
		slog.Warn("[DEBUG] AuthenticatePrivateKeyJWT: assertion verification failed", "client_id", client.GetID(), "error", err)
		return nil, protocol.ErrInvalidClient().WithDescription("invalid client_assertion").WithParent(err)
	}

	return client, nil
}

// FetchJWKSFromURI fetches and parses a JWKS from a remote URI.
// If allowPrivateIPs is false, the URI is validated to prevent SSRF attacks.
func FetchJWKSFromURI(uri string, skipTLSVerify, allowPrivateIPs bool) ([]jwk.Key, error) {
	if !allowPrivateIPs {
		if err := ValidateRemoteURL(uri); err != nil {
			return nil, fmt.Errorf("invalid jwks_uri: %w", err)
		}
	}
	client := NewHTTPClient(skipTLSVerify)
	resp, err := client.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks_uri: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks_uri returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read jwks_uri response: %w", err)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwks_uri response: %w", err)
	}
	var keys []jwk.Key
	for i := range set.Len() {
		key, _ := set.Key(i)
		keys = append(keys, key)
	}
	return keys, nil
}
