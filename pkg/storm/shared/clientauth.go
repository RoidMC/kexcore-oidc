package shared

import (
	"context"
	"net/http"
	"net/url"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// ClientStore is the minimal interface needed for client authentication.
type ClientStore interface {
	GetClientByClientID(ctx context.Context, clientID string) (Client, error)
	AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error
}

// Client is the minimal client interface used by ClientAuthHelper.
type Client interface {
	GetID() string
	AuthMethod() protocol.AuthMethod
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
// It supports both Basic Auth and POST body credentials.
//
// Plugins that need client authentication can use this helper or implement
// their own logic for special cases (e.g., JWT Profile grants).
type ClientAuthHelper struct {
	store ClientStore
}

// NewClientAuthHelper creates a helper backed by the given store.
func NewClientAuthHelper(store ClientStore) *ClientAuthHelper {
	return &ClientAuthHelper{store: store}
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
// verifies them against the store.
//
// Returns protocol.ErrInvalidClient if authentication fails.
func (h *ClientAuthHelper) AuthenticateClient(r *http.Request) (Client, error) {
	if err := r.ParseForm(); err != nil {
		return nil, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
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
