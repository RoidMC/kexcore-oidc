// Package userinfo implements the OIDC UserInfo endpoint plugin.
//
// It handles GET/POST /userinfo (OIDC Core §5.3), returning claims
// about the authenticated end-user. Supports both JSON and JWT response
// formats (OIDC Core §5.3.2).
package userinfo

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

// DefaultUserInfoJWTLifetime is the default expiration for UserInfo JWTs.
const DefaultUserInfoJWTLifetime = 5 * time.Minute

// Plugin implements the OIDC UserInfo endpoint.
type Plugin struct {
	store             storm.UserinfoStore
	cnfLookup         storm.TokenCNFLookup              // optional, enables sender-constrained token verification
	clientLookup      storm.TokenClientProvider         // optional, enables JWT response (aud claim)
	responseAlgLookup storm.UserInfoResponseAlgProvider // optional, per-client userinfo_signed_response_alg
	crypto            storm.UniCrypto
	keyStore          storm.KeyStore
	endpointConfigs   shared.EndpointConfigMap // endpoint configurations (optional)
}

// Config holds the dependencies for the UserInfo plugin.
type Config struct {
	Store        storm.UserinfoStore
	CNFLookup    storm.TokenCNFLookup      // optional, enables DPoP/mTLS token binding verification
	ClientLookup storm.TokenClientProvider // optional, enables JWT response (aud claim)
	Crypto       storm.UniCrypto
	KeyStore     storm.KeyStore
}

// New creates a new UserInfo plugin from a PluginContext.
func New(ctx *storm.PluginContext) *Plugin {
	p := &Plugin{
		store:           ctx.Storage.(storm.UserinfoStore),
		crypto:          ctx.Crypto,
		keyStore:        ctx.Storage.(storm.KeyStore),
		endpointConfigs: ctx.EndpointConfigs,
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
	if ra, ok := ctx.Storage.(storm.UserInfoResponseAlgProvider); ok {
		p.responseAlgLookup = ra
		slog.Default().Debug("userinfo: responseAlgLookup enabled (UserInfoResponseAlgProvider detected)")
	}
	return p
}

// NewWithConfig creates a new UserInfo plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	return &Plugin{
		store:        cfg.Store,
		cnfLookup:    cfg.CNFLookup,
		clientLookup: cfg.ClientLookup,
		crypto:       cfg.Crypto,
		keyStore:     cfg.KeyStore,
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
	userinfoPath := p.getRoutePath("userinfo", "/userinfo")
	r.Get(userinfoPath, p.handle)
	r.Post(userinfoPath, p.handle)
}

// Contribute returns the discovery fields for the userinfo endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.UserinfoEndpoint = p.resolveEndpoint(ctx, "userinfo", "/userinfo")

	// OIDC Discovery §3: advertise JWT response support when signing keys are available.
	if p.keyStore != nil {
		if algs, err := p.keyStore.SignatureAlgorithms(ctx); err == nil && len(algs) > 0 {
			cfg.UserinfoSigningAlgValuesSupported = algs
		}
	}
}

// resolveEndpoint resolves the absolute URL for the given endpoint.
// If EndpointConfigs is configured, it uses that; otherwise it falls back
// to the default behavior of building the URL from the issuer in context.
func (p *Plugin) resolveEndpoint(ctx context.Context, endpointName, defaultPath string) string {
	// Check if there's a custom discovery URL configured
	if p.endpointConfigs != nil {
		defaultURL := shared.EndpointURL(ctx, protocol.NewEndpoint(defaultPath))
		return p.endpointConfigs.GetDiscoveryURL(endpointName, defaultURL)
	}
	return shared.EndpointURL(ctx, protocol.NewEndpoint(defaultPath))
}

// getRoutePath returns the route path for the given endpoint.
// If EndpointConfigs is configured, it uses that; otherwise it returns defaultPath.
func (p *Plugin) getRoutePath(endpointName, defaultPath string) string {
	if p.endpointConfigs != nil {
		return p.endpointConfigs.GetRoutePath(endpointName, defaultPath)
	}
	return defaultPath
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	// FAPI 2.0 §6.2.1-11 / FAPI 1.0 Advanced §8.4.3: echo x-fapi-interaction-id.
	// If not present in request, generate a new UUID for the response.
	if interactionID := r.Header.Get("x-fapi-interaction-id"); interactionID != "" {
		w.Header().Set("x-fapi-interaction-id", interactionID)
	} else {
		w.Header().Set("x-fapi-interaction-id", uuid.NewString())
	}

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
		slog.Debug("userinfo ResolveToken FAILED", "access_token_len", len(accessToken))
		shared.WriteError(w, r, shared.NewStatusError(protocol.ErrInvalidRequest().WithDescription("invalid access token"), http.StatusUnauthorized), nil)
		return
	}
	slog.Debug("userinfo ResolveToken PASSED", "tokenID", tokenID, "subject", subject)

	// RFC 9449 §7.1: when a DPoP proof is presented to a resource server,
	// the ath claim MUST be present and MUST match base64url(SHA-256(access_token)).
	if proof := shared.DPoPFromContext(r.Context()); proof != nil {
		if err := shared.ValidateDPoPProofATH(proof, accessToken); err != nil {
			errMsg := err.Error()
			shared.WriteError(w, r, shared.NewStatusError(
				protocol.ErrInvalidRequest().WithDescription("%s", errMsg), http.StatusBadRequest), nil)
			return
		}
	}

	// RFC 8705 §5 / RFC 9449 §7.2: verify sender-constrained token binding.
	// If the token has a cnf claim, the request MUST prove possession of the
	// corresponding key (DPoP jkt or mTLS x5t#S256).
	slog.Debug("userinfo sender-constraining check",
		"tokenID", tokenID,
		"cnfLookup_nil", p.cnfLookup == nil,
		"has_client_cert", shared.ClientCertFromContext(r.Context()) != nil,
		"has_dpop", shared.DPoPFromContext(r.Context()) != nil,
	)
	if p.cnfLookup != nil {
		if cnf, err := p.cnfLookup.TokenCNF(r.Context(), tokenID); err == nil && len(cnf) > 0 {
			slog.Debug("userinfo cnf claim retrieved", "cnf", fmt.Sprintf("%v", cnf))
			if err := shared.VerifyTokenBinding(r.Context(), cnf); err != nil {
				slog.Debug("userinfo VerifyTokenBinding FAILED", "error", err)
				shared.WriteError(w, r, shared.NewStatusError(err, http.StatusUnauthorized), nil)
				return
			}
			slog.Debug("userinfo VerifyTokenBinding PASSED")
		} else {
			slog.Debug("userinfo cnf claim empty or error", "err", err, "cnf_len", len(cnf))
		}
	} else {
		slog.Debug("userinfo cnfLookup is nil, skipping sender-constraining check")
	}

	userInfo := new(protocol.UserInfo)

	// Check if the storage implements UserinfoFromRequestProvider for richer
	// per-request claims (Zitadel's CanSetUserinfoFromRequest equivalent).
	// When available, this takes priority over SetUserinfoFromToken.
	if ufrProvider, ok := p.store.(storm.UserinfoFromRequestProvider); ok {
		if err := ufrProvider.SetUserinfoFromRequest(r.Context(), userInfo, tokenID, subject, r.Header.Get("Origin"), nil); err != nil {
			slog.Debug("userinfo SetUserinfoFromRequest FAILED", "tokenID", tokenID, "subject", subject, "error", err)
			shared.WriteError(w, r, shared.NewStatusError(protocol.ErrInvalidRequest().WithDescription("invalid access token"), http.StatusUnauthorized), nil)
			return
		}
		slog.Debug("userinfo SetUserinfoFromRequest PASSED", "tokenID", tokenID, "subject", subject, "sub", userInfo.Subject)
	} else {
		if err := p.store.SetUserinfoFromToken(r.Context(), userInfo, tokenID, subject, r.Header.Get("Origin")); err != nil {
			slog.Debug("userinfo SetUserinfoFromToken FAILED", "tokenID", tokenID, "subject", subject, "error", err)
			shared.WriteError(w, r, shared.NewStatusError(protocol.ErrInvalidRequest().WithDescription("invalid access token"), http.StatusUnauthorized), nil)
			return
		}
		slog.Debug("userinfo SetUserinfoFromToken PASSED", "tokenID", tokenID, "subject", subject, "sub", userInfo.Subject)
	}

	// OIDC Core §5.3.2: response MUST contain the "sub" claim
	if userInfo.Subject == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("user not found"), nil)
		return
	}

	// Note: Scope-based claim filtering is the responsibility of the storage
	// implementation in SetUserinfoFromToken. The plugin does not enforce
	// filtering here — it serializes whatever the storage populates.

	// OIDC Core §5.3.2: return signed JWT when:
	// 1. Client registered userinfo_signed_response_alg (MUST), OR
	// 2. Accept header requests application/jwt (MAY)
	// AND signing keys + client lookup are available.
	shouldReturnJWT := false
	if p.clientLookup != nil && p.keyStore != nil {
		clientID, _ := p.clientLookup.TokenClientID(r.Context(), tokenID)
		// Check client's registered algorithm
		if clientID != "" && p.responseAlgLookup != nil {
			if alg, err := p.responseAlgLookup.UserInfoResponseAlg(r.Context(), clientID); err == nil && alg != "" {
				shouldReturnJWT = true
			}
		}
		// Check Accept header
		if !shouldReturnJWT && strings.Contains(r.Header.Get("Accept"), "application/jwt") {
			shouldReturnJWT = true
		}
	}
	if shouldReturnJWT {
		if err := p.writeJWTResponse(w, r, userInfo, tokenID); err != nil {
			slog.Default().Warn("userinfo JWT response failed, falling back to JSON", "error", err)
		} else {
			return
		}
	}

	shared.SetUserInfoHeaders(w)
	shared.JSONResponse(w, userInfo, http.StatusOK)
}

// extractAccessToken extracts the access token from the request.
// Supports both Bearer (RFC 6750) and DPoP (RFC 9449) authorization schemes.
// The auth-scheme is case-insensitive per RFC 6750 §1.1.
func extractAccessToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	authLower := strings.ToLower(auth)
	if strings.HasPrefix(authLower, "bearer ") {
		return auth[len("bearer "):]
	}
	if strings.HasPrefix(authLower, "dpop ") {
		return auth[len("dpop "):]
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

	// If the client specifies a preferred userinfo signing algorithm, try to
	// use a matching signing key (OIDC Core §5.3.2: userinfo_signed_response_alg).
	if p.responseAlgLookup != nil {
		if alg, err := p.responseAlgLookup.UserInfoResponseAlg(r.Context(), clientID); err == nil && alg != "" {
			if algStore, ok := p.keyStore.(storm.SigningKeyByAlgProvider); ok {
				if algKey, err := algStore.SigningKeyByAlg(r.Context(), alg); err == nil {
					signingKey = algKey
				}
			}
		}
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
