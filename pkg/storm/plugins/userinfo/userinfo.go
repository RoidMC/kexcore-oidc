// Package userinfo implements the OIDC UserInfo endpoint plugin.
//
// It handles GET/POST /userinfo (OIDC Core §5.3), returning claims
// about the authenticated end-user.
package userinfo

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the OIDC UserInfo endpoint.
type Plugin struct {
	store    storm.UserinfoStore
	crypto   storm.UniCrypto
	keyStore protocol.KeyStore
}

// Config holds the dependencies for the UserInfo plugin.
type Config struct {
	Store    storm.UserinfoStore
	Crypto   storm.UniCrypto
	KeyStore protocol.KeyStore
}

// New creates a new UserInfo plugin from a PluginContext.
func New(ctx *storm.PluginContext) *Plugin {
	return &Plugin{
		store:    ctx.Storage.(storm.UserinfoStore),
		crypto:   ctx.Crypto,
		keyStore: ctx.Storage.(storm.KeyStore),
	}
}

// NewWithConfig creates a new UserInfo plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	return &Plugin{
		store:    cfg.Store,
		crypto:   cfg.Crypto,
		keyStore: cfg.KeyStore,
	}
}

// init self-registers the userinfo plugin in the global registry.
func init() {
	storm.RegisterPlugin("userinfo", storm.PriorityUserinfo, func(ctx *storm.PluginContext) storm.Plugin {
		return New(ctx)
	})
}

// Category returns CategoryStandard — userinfo is optional but enabled by default.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string {
	return []string{"UserinfoStore", "KeyStore"}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "userinfo" }

// Register installs the /userinfo route.
//
// OIDC standard endpoint: GET/POST /userinfo (OIDC Core §5.3)
func (p *Plugin) Register(r chi.Router) {
	r.Get("/userinfo", p.handle)
	r.Post("/userinfo", p.handle)
}

// Contribute returns the discovery fields for the userinfo endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"userinfo_endpoint": shared.EndpointURL(ctx, protocol.NewEndpoint("/userinfo")),
	}
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	// Extract access token from Authorization header or form body
	accessToken := extractAccessToken(r)
	if accessToken == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("access token is missing"), nil)
		return
	}

	// Resolve the token to tokenID and subject
	// Supports opaque tokens (standard + GM/T JWE) and JWT access tokens.
	tokenID, subject, ok := resolveAccessToken(r.Context(), p.crypto, p.keyStore, shared.IssuerFromContext(r.Context()), accessToken)
	if !ok {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("invalid access token"), nil)
		return
	}

	userInfo := new(protocol.UserInfo)
	if err := p.store.SetUserinfoFromToken(r.Context(), userInfo, tokenID, subject, r.Header.Get("Origin")); err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	// OIDC Core §5.3.2: response MUST contain the "sub" claim
	if userInfo.Subject == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("user not found"), nil)
		return
	}

	// Set OIDC-required headers (OIDC Core §5.3.2, RFC 6750 §3)
	shared.SetUserInfoHeaders(w)
	shared.JSONResponse(w, userInfo, http.StatusOK)
}

// extractAccessToken extracts the bearer token from the request.
func extractAccessToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	// Fallback to form body for POST requests
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			return r.Form.Get("access_token")
		}
	}
	return ""
}

// gmDecryptor is an optional interface for GM/T JWE decryption.
// Implementations that support GM/T can implement this interface.
type gmDecryptor interface {
	SM2DecryptJWE(ctx context.Context, compact string) ([]byte, error)
}

// resolveAccessToken resolves an opaque access token to its tokenID and subject.
// Supports standard decrypted tokens, GM/T JWE tokens, and JWT access tokens.
func resolveAccessToken(ctx context.Context, crypto storm.UniCrypto, keyStore protocol.KeyStore, issuer, accessToken string) (tokenID, subject string, ok bool) {
	var plaintext []byte
	var err error

	// Try GM/T JWE decryption first (SM2+SM4-GCM per GM/T 0125.3)
	if gm, ok := crypto.(gmDecryptor); ok {
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
		v := &protocol.AccessTokenVerifier{
			Issuer:   issuer,
			KeyStore: keyStore,
		}
		return protocol.VerifyAccessToken(ctx, accessToken, v)
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
