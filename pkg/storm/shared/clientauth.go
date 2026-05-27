package shared

import (
	"context"
	"net/http"
	"net/url"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
)

// ClientStore is the minimal interface needed for client authentication.
type ClientStore interface {
	GetClientByClientID(ctx context.Context, clientID string) (Client, error)
	AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error
}

// Client is the minimal client interface used by ClientAuthHelper.
type Client interface {
	GetID() string
	AuthMethod() oidc.AuthMethod
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

// AuthenticateClient extracts client credentials from the request and
// verifies them against the store.
//
// Returns oidc.ErrInvalidClient if authentication fails.
func (h *ClientAuthHelper) AuthenticateClient(r *http.Request) (Client, error) {
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}

	clientID, clientSecret := r.Form.Get("client_id"), r.Form.Get("client_secret")

	// Basic auth takes precedence over form data.
	if id, secret, ok := r.BasicAuth(); ok {
		var err error
		clientID, err = url.QueryUnescape(id)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
		clientSecret, err = url.QueryUnescape(secret)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
	}

	if clientID == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("client_id missing")
	}

	client, err := h.store.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithParent(err)
	}

	if client.AuthMethod() != oidc.AuthMethodNone {
		if err := h.store.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			return nil, err
		}
	}

	return client, nil
}

// ParseClientCredentials extracts client credentials from the request
// without verifying them against the store.
// Returns oidc.ErrInvalidRequest if no credentials are found.
func ParseClientCredentials(r *http.Request) (clientID, clientSecret string, err error) {
	if err := r.ParseForm(); err != nil {
		return "", "", oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}

	clientID, clientSecret = r.Form.Get("client_id"), r.Form.Get("client_secret")

	if id, secret, ok := r.BasicAuth(); ok {
		var e error
		clientID, e = url.QueryUnescape(id)
		if e != nil {
			return "", "", oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(e)
		}
		clientSecret, e = url.QueryUnescape(secret)
		if e != nil {
			return "", "", oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(e)
		}
	}

	if clientID == "" {
		return "", "", oidc.ErrInvalidRequest().WithDescription("client_id missing")
	}

	return clientID, clientSecret, nil
}
