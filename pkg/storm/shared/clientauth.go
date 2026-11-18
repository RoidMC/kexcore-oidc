package shared

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
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

// ClientSecretProvider is optionally implemented by Client when
// client_secret_jwt is allowed. The returned secret is used as the
// HS256/HS384/HS512 MAC key for client assertions.
//
// The SDK never logs or returns this value; implementations should treat it
// with the same care as the secret used for client_secret_basic/post.
type ClientSecretProvider interface {
	ClientSecret() string
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

	// --- Method 1: client_assertion (private_key_jwt / client_secret_jwt) ---
	if assertionType := r.Form.Get("client_assertion_type"); assertionType == protocol.ClientAssertionTypeJWTAssertion {
		assertion := r.Form.Get("client_assertion")
		if assertion == "" {
			return nil, protocol.ErrInvalidClient().WithDescription("client_assertion is missing")
		}
		getClient := func(ctx context.Context, cid string) (Client, error) {
			return h.store.GetClientByClientID(ctx, cid)
		}
		// RFC 7523 §3: the assertion audience is the issuer (or token endpoint).
		// The issuer middleware is the only reliable source here because this
		// helper is shared by token, introspection, revocation and device.
		getAudiences := func(client Client) []string {
			if issuer := IssuerFromContext(r.Context()); issuer != "" {
				return []string{issuer}
			}
			return nil
		}
		alg := assertionAlgorithm(assertion)
		if strings.HasPrefix(alg, "HS") {
			client, err := AuthenticateClientSecretJWT(r, getClient, assertion, alg, getAudiences)
			if err != nil {
				return nil, protocol.ErrInvalidClient().WithParent(err)
			}
			return client, nil
		}
		client, err := AuthenticatePrivateKeyJWT(r, getClient, assertion, getAudiences, h.skipTLSCertVerify, h.allowPrivateIPs)
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

	// RFC 7523 §2.2 / FAPI 2.0: a client registered for a JWT-based method MUST
	// authenticate via client_assertion. Reaching this point means the request
	// carries no assertion, so falling back to client_secret authentication
	// would accept requests that omit client authentication entirely at the
	// introspection, revocation, and device endpoints.
	if method := client.AuthMethod(); method == protocol.AuthMethodPrivateKeyJWT || method == protocol.AuthMethodClientSecretJWT {
		return nil, protocol.ErrInvalidClient().WithDescription("%s", "client_assertion required for "+string(method)+" client")
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

	// --- Method 2b: self_signed_tls_client_auth (mTLS certificate) — RFC 8705 §2.2 ---
	if client.AuthMethod() == protocol.AuthMethodSelfSignedTLSAuth {
		cert := ClientCertFromContext(r.Context())
		if cert == nil {
			return nil, protocol.ErrInvalidClient().WithDescription("mTLS client certificate is required for self_signed_tls_client_auth client")
		}
		if err := VerifySelfSignedTLSClientAuth(client, cert, h.skipTLSCertVerify, h.allowPrivateIPs); err != nil {
			return nil, protocol.ErrInvalidClient().WithParent(err)
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

// VerifySelfSignedTLSClientAuth implements RFC 8705 §2.2 (self-signed
// certificate mutual TLS client authentication): the presented certificate
// must be self-signed, and its public key must match one of the client's
// registered JWKS keys (jwks_uri preferred, static jwks fallback).
func VerifySelfSignedTLSClientAuth(client Client, cert *x509.Certificate, skipTLSCertVerify, allowPrivateIPs bool) error {
	// Self-signed means the certificate verifies under its own public key;
	// CheckSignatureFrom also validates the signature itself.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("certificate is not self-signed: %w", err)
	}

	keys, err := clientJWKSKeys(client, skipTLSCertVerify, allowPrivateIPs)
	if err != nil {
		return err
	}

	certKey, err := jwk.Import[jwk.Key](cert.PublicKey)
	if err != nil {
		return fmt.Errorf("unsupported certificate public key type: %w", err)
	}
	certThumb, err := jwkThumbprint(certKey)
	if err != nil {
		return fmt.Errorf("cannot compute certificate key thumbprint: %w", err)
	}
	for _, k := range keys {
		t, err := jwkThumbprint(k)
		if err != nil {
			continue
		}
		if t == certThumb {
			return nil
		}
	}
	return fmt.Errorf("certificate public key does not match any registered jwks key")
}

// clientJWKSKeys resolves the client's registered keys: jwks_uri first (falling
// back to static jwks when the fetch fails), then static jwks — same resolution
// order as AuthenticatePrivateKeyJWT.
func clientJWKSKeys(client Client, skipTLSCertVerify, allowPrivateIPs bool) ([]jwk.Key, error) {
	if uriProvider, ok := client.(JWKSURIProvider); ok && uriProvider.ClientJWKSURI() != "" {
		if keys, err := FetchJWKSFromURI(uriProvider.ClientJWKSURI(), skipTLSCertVerify, allowPrivateIPs); err == nil {
			return keys, nil
		}
	}
	if ks, ok := client.(JWKSProvider); ok {
		if keys := ks.ClientJWKS(); len(keys) > 0 {
			return keys, nil
		}
	}
	return nil, fmt.Errorf("client has no registered jwks keys")
}

// jwkThumbprint computes the RFC 7638 JWK thumbprint (base64url, no padding).
func jwkThumbprint(key jwk.Key) (string, error) {
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumb), nil
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
	slog.Debug("AuthenticatePrivateKeyJWT: audience check",
		"client_id", client.GetID(),
		"allowed_audiences", allowedAudiences,
	)

	// Step 5: Verify the assertion with the client's keys.
	if err := protocol.VerifyJWTAssertion(r.Context(), assertion, allowedAudiences, clientKeys, 10*time.Second); err != nil {
		slog.Debug("AuthenticatePrivateKeyJWT: assertion verification failed", "client_id", client.GetID(), "error", err)
		return nil, protocol.ErrInvalidClient().WithDescription("invalid client_assertion").WithParent(err)
	}

	return client, nil
}

// AuthenticateClientSecretJWT verifies an RFC 7523 client assertion signed with
// the client secret (HS256/HS384/HS512). The client must be registered for
// client_secret_jwt and implement ClientSecretProvider.
func AuthenticateClientSecretJWT(r *http.Request, getClientByClientID func(ctx context.Context, clientID string) (Client, error), assertion, alg string, getAudiences func(client Client) []string) (Client, error) {
	switch alg {
	case "HS256", "HS384", "HS512":
	default:
		return nil, protocol.ErrInvalidClient().WithDescription("client_secret_jwt requires HS256, HS384 or HS512")
	}

	request := new(protocol.JWTTokenRequest)
	if _, err := protocol.ParseToken(assertion, request); err != nil {
		return nil, protocol.ErrInvalidClient().WithDescription("invalid client_assertion").WithParent(err)
	}
	if request.Issuer == "" {
		return nil, protocol.ErrInvalidClient().WithDescription("client_assertion missing iss claim")
	}

	client, err := getClientByClientID(r.Context(), request.Issuer)
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithParent(err)
	}
	if client.AuthMethod() != protocol.AuthMethodClientSecretJWT {
		return nil, protocol.ErrInvalidClient().WithDescription("client not configured for client_secret_jwt")
	}

	secretProvider, ok := client.(ClientSecretProvider)
	if !ok || secretProvider.ClientSecret() == "" {
		return nil, protocol.ErrInvalidClient().WithDescription("client does not support client_secret_jwt")
	}

	key, err := jwk.Import[jwk.Key]([]byte(secretProvider.ClientSecret()))
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithDescription("invalid client secret").WithParent(err)
	}

	var allowedAudiences []string
	if getAudiences != nil {
		allowedAudiences = getAudiences(client)
	}
	if err := protocol.VerifyJWTAssertion(r.Context(), assertion, allowedAudiences, []jwk.Key{key}, 10*time.Second); err != nil {
		return nil, protocol.ErrInvalidClient().WithDescription("invalid client_assertion").WithParent(err)
	}

	return client, nil
}

// AssertionAlgorithm returns the "alg" header of an unverified JWS. It is only
// used to route between HS (client_secret_jwt) and asymmetric
// (private_key_jwt) assertions; no claim of the assertion has been verified at
// this point.
func AssertionAlgorithm(assertion string) string {
	return assertionAlgorithm(assertion)
}

// assertionAlgorithm returns the "alg" header of an unverified JWS. It is only
// used to route between HS (client_secret_jwt) and asymmetric
// (private_key_jwt) verification; the signature is always verified afterwards.
func assertionAlgorithm(assertion string) string {
	msg, err := jws.Parse([]byte(assertion))
	if err != nil {
		return ""
	}
	_, alg := protocol.GetKeyIDAndAlg(msg)
	return alg
}

// FetchJWKSFromURI fetches and parses a JWKS from a remote URI.
// SSRF protections: pre-flight URL validation plus dial-time IP checks
// (see FetchRemoteURL), unless allowPrivateIPs is set (test-only).
func FetchJWKSFromURI(uri string, skipTLSVerify, allowPrivateIPs bool) ([]jwk.Key, error) {
	resp, err := FetchRemoteURL(uri, skipTLSVerify, allowPrivateIPs)
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
