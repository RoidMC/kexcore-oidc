// Package introspection implements the OAuth 2.0 Token Introspection endpoint plugin.
//
// It handles POST /introspect (RFC 7662 §2), allowing authorized clients
// to determine the active state and meta-information of an OAuth 2.0 token.
package introspection

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the Token Introspection endpoint.
type Plugin struct {
	store       storm.IntrospectStore
	clientStore storm.ClientStore
	crypto      storm.Crypto
	keyStore    shared.KeyStore
}

// Config holds the dependencies for the Introspection plugin.
type Config struct {
	Store       storm.IntrospectStore
	ClientStore storm.ClientStore
	Crypto      storm.Crypto
	KeyStore    shared.KeyStore
}

// New creates a new Introspection plugin.
func New(cfg Config) *Plugin {
	return &Plugin{
		store:       cfg.Store,
		clientStore: cfg.ClientStore,
		crypto:      cfg.Crypto,
		keyStore:    cfg.KeyStore,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "introspection" }

// Register installs the POST /introspect route.
//
// OAuth 2.0 standard endpoint: POST /introspect (RFC 7662 §2)
func (p *Plugin) Register(r chi.Router) {
	r.Post("/introspect", p.handle)
}

// Contribute returns the discovery fields for the introspection endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"introspection_endpoint": shared.IssuerURL(ctx, "/introspect"),
	}
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	// Authenticate the client
	clientID, clientSecret := r.Form.Get("client_id"), r.Form.Get("client_secret")
	if id, secret, ok := r.BasicAuth(); ok {
		var err error
		clientID, err = url.QueryUnescape(id)
		if err != nil {
			shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("invalid basic auth header"), nil)
			return
		}
		clientSecret, err = url.QueryUnescape(secret)
		if err != nil {
			shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("invalid basic auth header"), nil)
			return
		}
	}

	if clientID == "" {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithDescription("client authentication required"), nil)
		return
	}

	if err := p.clientStore.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("token is missing"), nil)
		return
	}

	// Resolve token to tokenID and subject
	// Supports opaque tokens (standard + GM/T JWE) and JWT access tokens.
	tokenID, subject, ok := resolveToken(r.Context(), p.crypto, p.keyStore, shared.IssuerFromContext(r.Context()), token)
	if !ok {
		// Return inactive token response per RFC 7662 §2.2
		shared.JSONResponse(w, &protocol.IntrospectionResponse{Active: false}, http.StatusOK)
		return
	}

	resp := &protocol.IntrospectionResponse{Active: true}
	if err := p.store.SetIntrospectionFromToken(r.Context(), resp, tokenID, subject, clientID); err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	shared.JSONResponse(w, resp, http.StatusOK)
}

// resolveToken resolves an opaque token to its tokenID and subject.
// Supports standard decrypted tokens, GM/T JWE tokens, and JWT access tokens.
func resolveToken(ctx context.Context, crypto storm.Crypto, keyStore shared.KeyStore, issuer, token string) (tokenID, subject string, ok bool) {
	var plaintext []byte
	var err error

	// Try GM/T JWE decryption first (SM2+SM4-GCM per GM/T 0125.3)
	if gm, ok := crypto.(storm.GMCrypto); ok {
		plaintext, err = gm.SM2DecryptJWE(ctx, token)
		if err == nil {
			return parseTokenParts(plaintext)
		}
	}

	// Standard opaque token decryption
	plaintext, err = crypto.Decrypt(ctx, []byte(token))
	if err == nil {
		return parseTokenParts(plaintext)
	}

	// Opaque decryption failed - try JWT access token verification (RFC 6750 §2.1)
	if keyStore != nil {
		v := &shared.AccessTokenVerifier{
			Issuer:   issuer,
			KeyStore: keyStore,
		}
		return shared.VerifyAccessToken(ctx, token, v)
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
