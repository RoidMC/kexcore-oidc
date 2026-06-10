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
	store         storm.UserinfoStore
	scopeProvider storm.TokenScopeProvider
	cnfLookup     storm.TokenCNFLookup // optional, enables sender-constrained token verification
	crypto        storm.UniCrypto
	keyStore      protocol.KeyStore
}

// Config holds the dependencies for the UserInfo plugin.
type Config struct {
	Store         storm.UserinfoStore
	ScopeProvider storm.TokenScopeProvider // optional, enables scope-based claim filtering
	CNFLookup     storm.TokenCNFLookup     // optional, enables DPoP/mTLS token binding verification
	Crypto        storm.UniCrypto
	KeyStore      protocol.KeyStore
}

// New creates a new UserInfo plugin from a PluginContext.
func New(ctx *storm.PluginContext) *Plugin {
	p := &Plugin{
		store:    ctx.Storage.(storm.UserinfoStore),
		crypto:   ctx.Crypto,
		keyStore: ctx.Storage.(storm.KeyStore),
	}
	if sp, ok := ctx.Storage.(storm.TokenScopeProvider); ok {
		p.scopeProvider = sp
	}
	if cl, ok := ctx.Storage.(storm.TokenCNFLookup); ok {
		p.cnfLookup = cl
	}
	return p
}

// NewWithConfig creates a new UserInfo plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	return &Plugin{
		store:         cfg.Store,
		scopeProvider: cfg.ScopeProvider,
		cnfLookup:     cfg.CNFLookup,
		crypto:        cfg.Crypto,
		keyStore:      cfg.KeyStore,
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
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.UserinfoEndpoint = shared.EndpointURL(ctx, protocol.NewEndpoint("/userinfo"))
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	// Extract access token from Authorization header or form body
	accessToken := extractAccessToken(r)
	if accessToken == "" {
		shared.WriteError(w, r, shared.NewStatusError(protocol.ErrInvalidRequest().WithDescription("access token is missing"), http.StatusUnauthorized), nil)
		return
	}

	// Resolve the token to tokenID and subject
	// Supports opaque tokens (standard + GM/T JWE) and JWT access tokens.
	tokenID, subject, ok := storm.ResolveToken(r.Context(), p.crypto, p.keyStore, shared.IssuerFromContext(r.Context()), accessToken)
	if !ok {
		shared.WriteError(w, r, shared.NewStatusError(protocol.ErrInvalidRequest().WithDescription("invalid access token"), http.StatusUnauthorized), nil)
		return
	}

	// RFC 8705 §5 / RFC 9449 §7.2: verify sender-constrained token binding.
	// If the token has a cnf claim, the request MUST prove possession of the
	// corresponding key (DPoP jkt or mTLS x5t#S256).
	if p.cnfLookup != nil {
		if cnf, err := p.cnfLookup.TokenCNF(r.Context(), tokenID); err == nil && len(cnf) > 0 {
			if err := shared.VerifyTokenBinding(r.Context(), cnf); err != nil {
				shared.WriteError(w, r, shared.NewStatusError(err, http.StatusUnauthorized), nil)
				return
			}
		}
	}

	userInfo := new(protocol.UserInfo)
	if err := p.store.SetUserinfoFromToken(r.Context(), userInfo, tokenID, subject, r.Header.Get("Origin")); err != nil {
		shared.WriteError(w, r, shared.NewStatusError(protocol.ErrInvalidRequest().WithDescription("invalid access token"), http.StatusUnauthorized), nil)
		return
	}

	// OIDC Core §5.3.2: response MUST contain the "sub" claim
	if userInfo.Subject == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("user not found"), nil)
		return
	}

	// OIDC Core §5.4: filter standard claims by scope.
	// If the storage implements TokenScopeProvider, we enforce scope filtering
	// at the protocol level. Custom claims in the Claims map are always preserved.
	if p.scopeProvider != nil {
		if scopes, err := p.scopeProvider.TokenScopes(r.Context(), tokenID); err == nil {
			userInfo.FilterByScopes(scopes)
		}
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
