// Package userinfo implements the OIDC UserInfo endpoint plugin.
//
// It handles GET/POST /userinfo (OIDC Core §5.3), returning claims
// about the authenticated end-user. Supports both JSON and JWT response
// formats (OIDC Core §5.3.2).
package userinfo

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// DefaultUserInfoJWTLifetime is the default expiration for UserInfo JWTs.
const DefaultUserInfoJWTLifetime = 5 * time.Minute

// Plugin implements the OIDC UserInfo endpoint.
type Plugin struct {
	store         storm.UserinfoStore
	scopeProvider storm.TokenScopeProvider
	cnfLookup     storm.TokenCNFLookup      // optional, enables sender-constrained token verification
	clientLookup  storm.TokenClientProvider // optional, enables JWT response (aud claim)
	crypto        storm.UniCrypto
	keyStore      storm.KeyStore
}

// Config holds the dependencies for the UserInfo plugin.
type Config struct {
	Store         storm.UserinfoStore
	ScopeProvider storm.TokenScopeProvider  // optional, enables scope-based claim filtering
	CNFLookup     storm.TokenCNFLookup      // optional, enables DPoP/mTLS token binding verification
	ClientLookup  storm.TokenClientProvider // optional, enables JWT response (aud claim)
	Crypto        storm.UniCrypto
	KeyStore      storm.KeyStore
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
	if cp, ok := ctx.Storage.(storm.TokenClientProvider); ok {
		p.clientLookup = cp
		slog.Default().Debug("userinfo: clientLookup enabled (TokenClientProvider detected)")
	} else {
		slog.Default().Warn("userinfo: clientLookup NOT available — JWT responses disabled, storage does not implement TokenClientProvider")
	}
	return p
}

// NewWithConfig creates a new UserInfo plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	return &Plugin{
		store:         cfg.Store,
		scopeProvider: cfg.ScopeProvider,
		cnfLookup:     cfg.CNFLookup,
		clientLookup:  cfg.ClientLookup,
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

	// OIDC Discovery §3: advertise JWT response support when signing keys are available.
	if p.keyStore != nil {
		if algs, err := p.keyStore.SignatureAlgorithms(ctx); err == nil && len(algs) > 0 {
			cfg.UserinfoSigningAlgValuesSupported = algs
		}
	}
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

	// OIDC Core §5.3.2: when signing keys are available, the response MUST be a signed JWT.
	// Accept header cannot override this — the server MAY also support JSON, but signed
	// responses are always JWT.
	if p.clientLookup != nil && p.keyStore != nil {
		if err := p.writeJWTResponse(w, r, userInfo, tokenID); err != nil {
			slog.Default().Warn("userinfo JWT response failed, falling back to JSON", "error", err)
		} else {
			return
		}
	}

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

// writeJWTResponse signs the UserInfo as a JWT and writes it to the response.
// Per OIDC Core §5.3.2, the JWT contains:
//   - iss: the issuer URL
//   - aud: the client_id that the token was issued to
//   - sub: the subject
//   - exp, iat: standard time claims
//   - All UserInfo claims
func (p *Plugin) writeJWTResponse(w http.ResponseWriter, r *http.Request, userInfo *protocol.UserInfo, tokenID string) error {
	issuer := shared.IssuerFromContext(r.Context())
	if issuer == "" {
		return ErrNoIssuer
	}

	clientID, err := p.clientLookup.TokenClientID(r.Context(), tokenID)
	if err != nil || clientID == "" {
		return ErrNoClientID
	}

	signingKey, err := p.keyStore.SigningKey(r.Context())
	if err != nil {
		return err
	}

	now := time.Now()
	token := jwt.New()
	_ = token.Set("iss", issuer)
	_ = token.Set("aud", clientID)
	_ = token.Set("sub", userInfo.Subject)
	_ = token.Set("iat", now.Unix())
	_ = token.Set("exp", now.Add(DefaultUserInfoJWTLifetime).Unix())

	// Add all UserInfo claims as JWT claims
	if userInfo.Name != "" {
		_ = token.Set("name", userInfo.Name)
	}
	if userInfo.GivenName != "" {
		_ = token.Set("given_name", userInfo.GivenName)
	}
	if userInfo.FamilyName != "" {
		_ = token.Set("family_name", userInfo.FamilyName)
	}
	if userInfo.MiddleName != "" {
		_ = token.Set("middle_name", userInfo.MiddleName)
	}
	if userInfo.Nickname != "" {
		_ = token.Set("nickname", userInfo.Nickname)
	}
	if userInfo.PreferredUsername != "" {
		_ = token.Set("preferred_username", userInfo.PreferredUsername)
	}
	if userInfo.Profile != "" {
		_ = token.Set("profile", userInfo.Profile)
	}
	if userInfo.Picture != "" {
		_ = token.Set("picture", userInfo.Picture)
	}
	if userInfo.Website != "" {
		_ = token.Set("website", userInfo.Website)
	}
	if userInfo.Email != "" {
		_ = token.Set("email", userInfo.Email)
	}
	if userInfo.EmailVerified {
		_ = token.Set("email_verified", true)
	}
	if userInfo.Gender != "" {
		_ = token.Set("gender", userInfo.Gender)
	}
	if userInfo.Birthdate != "" {
		_ = token.Set("birthdate", userInfo.Birthdate)
	}
	if userInfo.Zoneinfo != "" {
		_ = token.Set("zoneinfo", userInfo.Zoneinfo)
	}
	if userInfo.Locale != nil {
		_ = token.Set("locale", userInfo.Locale.Tag().String())
	}
	if userInfo.PhoneNumber != "" {
		_ = token.Set("phone_number", userInfo.PhoneNumber)
	}
	if userInfo.PhoneNumberVerified {
		_ = token.Set("phone_number_verified", true)
	}
	if userInfo.UpdatedAt != 0 {
		_ = token.Set("updated_at", int64(userInfo.UpdatedAt))
	}
	if userInfo.Address != nil {
		_ = token.Set("address", userInfo.Address)
	}

	// Add custom claims
	for k, v := range userInfo.Claims {
		_ = token.Set(k, v)
	}

	alg := determineAlg(signingKey.Algorithm())
	signed, err := jwt.Sign(token, jwt.WithKey(alg, signingKey.Key()))
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write([]byte(signed))
	return nil
}

// determineAlg maps the key algorithm string to jwa.SignatureAlgorithm.
func determineAlg(alg string) jwa.SignatureAlgorithm {
	if jwaAlg, ok := jwa.LookupSignatureAlgorithm(alg); ok {
		return jwaAlg
	}
	return jwa.RS256()
}

// sentinel errors for JWT response fallback.
var (
	ErrNoIssuer   = &userInfoJWTError{"issuer not found in context"}
	ErrNoClientID = &userInfoJWTError{"client_id not found for token"}
)

type userInfoJWTError struct {
	msg string
}

func (e *userInfoJWTError) Error() string { return e.msg }
