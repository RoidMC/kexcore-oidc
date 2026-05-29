// Package revocation implements the OAuth 2.0 Token Revocation endpoint plugin.
//
// It handles POST /revoke (RFC 7009 §2), allowing clients to invalidate
// access tokens and refresh tokens.
package revocation

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/codec"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the Token Revocation endpoint.
type Plugin struct {
	store       storm.RevocationStore
	clientStore storm.ClientStore
	crypto      storm.Crypto
	keyStore    shared.KeyStore
	converters  map[reflect.Type]codec.Converter
}

// Config holds the dependencies for the Revocation plugin.
type Config struct {
	Store       storm.RevocationStore
	ClientStore storm.ClientStore
	Crypto      storm.Crypto
	KeyStore    shared.KeyStore
	Converters  map[reflect.Type]codec.Converter
}

// New creates a new Revocation plugin.
func New(cfg Config) *Plugin {
	return &Plugin{
		store:       cfg.Store,
		clientStore: cfg.ClientStore,
		crypto:      cfg.Crypto,
		keyStore:    cfg.KeyStore,
		converters:  cfg.Converters,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "revocation" }

// Register installs the POST /revoke route.
//
// OAuth 2.0 standard endpoint: POST /revoke (RFC 7009 §2)
func (p *Plugin) Register(r chi.Router) {
	r.Post("/revoke", p.handle)
}

// Contribute returns the discovery fields for the revocation endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"revocation_endpoint": shared.IssuerURL(ctx, "/revoke"),
	}
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	token := r.Form.Get("token")
	tokenTypeHint := r.Form.Get("token_type_hint")

	// Authenticate the client
	clientID, err := p.authenticateClient(r)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	var subject string
	doDecrypt := true

	// If hint is not access_token, try refresh token first
	if tokenTypeHint != "access_token" {
		userID, tokenID, err := p.store.GetRefreshTokenInfo(r.Context(), clientID, token)
		if err != nil {
			if !errors.Is(err, ErrInvalidRefreshToken) {
				shared.WriteError(w, r, protocol.ErrServerError().WithParent(err), nil)
				return
			}
			// Invalid refresh token, try as access token
		} else {
			token = tokenID
			subject = userID
			doDecrypt = false
		}
	}

	if doDecrypt {
		tokenID, userID, ok := resolveTokenForRevocation(r.Context(), p.crypto, p.keyStore, shared.IssuerFromContext(r.Context()), token)
		if ok {
			token = tokenID
			subject = userID
		}
	}

	if err := p.store.RevokeToken(r.Context(), token, subject, clientID); err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	// RFC 7009 §2.2: The revocation endpoint responds with HTTP 200 for both
	// success and "token not found" cases.
	w.WriteHeader(http.StatusOK)
}

func (p *Plugin) authenticateClient(r *http.Request) (string, error) {
	clientID, clientSecret := r.Form.Get("client_id"), r.Form.Get("client_secret")

	if id, secret, ok := r.BasicAuth(); ok {
		var err error
		clientID, err = url.QueryUnescape(id)
		if err != nil {
			return "", protocol.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
		clientSecret, err = url.QueryUnescape(secret)
		if err != nil {
			return "", protocol.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
	}

	if clientID == "" {
		return "", protocol.ErrInvalidClient().WithDescription("client authentication required")
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		return "", protocol.ErrInvalidClient().WithParent(err)
	}

	if client.AuthMethod() != protocol.AuthMethodNone {
		if err := p.clientStore.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			return "", err
		}
	}

	return clientID, nil
}

// resolveTokenForRevocation resolves an access token to its tokenID and subject.
// Supports standard decrypted tokens, GM/T JWE tokens, and JWT access tokens.
func resolveTokenForRevocation(ctx context.Context, crypto storm.Crypto, keyStore shared.KeyStore, issuer, accessToken string) (tokenID, subject string, ok bool) {
	var plaintext []byte
	var err error

	// Try GM/T JWE decryption first (SM2+SM4-GCM per GM/T 0125.3)
	if gm, ok := crypto.(storm.GMCrypto); ok {
		plaintext, err = gm.SM2DecryptJWE(ctx, accessToken)
		if err == nil {
			return parseTokenParts(plaintext)
		}
	}

	// Standard opaque token decryption
	plaintext, err = crypto.Decrypt(ctx, []byte(accessToken))
	if err == nil {
		return parseTokenParts(plaintext)
	}

	// Opaque decryption failed - try JWT access token verification (RFC 6750 §2.1)
	if keyStore != nil {
		v := &shared.AccessTokenVerifier{
			Issuer:   issuer,
			KeyStore: keyStore,
		}
		return shared.VerifyAccessToken(ctx, accessToken, v)
	}

	return "", "", false
}

// parseTokenParts splits "tokenID:subject" plaintext into its components.
func parseTokenParts(plaintext []byte) (tokenID, subject string, ok bool) {
	parts := strings.SplitN(string(plaintext), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// ErrInvalidRefreshToken is a sentinel error for invalid refresh tokens.
var ErrInvalidRefreshToken = errors.New("invalid refresh token")
