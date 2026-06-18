// Package token implements the OIDC Token endpoint plugin.
//
// It handles POST /token (RFC 6749 §3.2 / OIDC Core §3.1.3.1),
// supporting the following grant types:
//   - authorization_code (RFC 6749 §4.1.3, OIDC Core §3.1.3.1)
//   - refresh_token (RFC 6749 §6)
//   - client_credentials (RFC 6749 §4.4)
//   - urn:ietf:params:oauth:grant-type:jwt-bearer (RFC 7523 §2.1)
//   - urn:ietf:params:oauth:grant-type:device_code (RFC 8628 §3.4)
//   - urn:ietf:params:oauth:grant-type:token-exchange (RFC 8693)
package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// New creates a new Token plugin from a PluginContext.
func New(ctx *storm.PluginContext) *Plugin {
	p := &Plugin{
		tokenStore:         ctx.Storage.(storm.TokenStore),
		clientStore:        ctx.Storage.(storm.ClientStore),
		authStore:          ctx.Storage.(storm.AuthStore),
		crypto:             ctx.Crypto,
		keyStore:           ctx.Storage.(storm.KeyStore),
		decoder:            ctx.Decoder,
		logger:             slog.Default(),
		tracer:             ctx.Tracer,
		devicePollInterval: 5 * time.Second,
		requireDPoP:        ctx.RequireDPoP,
		requireMtls:        ctx.RequireMtls,
	}
	if das, ok := ctx.Storage.(storm.DeviceAuthStore); ok {
		p.deviceAuthStore = das
	}
	if cs, ok := ctx.Storage.(storm.CIBAStore); ok {
		p.cibaStore = cs
	}
	if pt, ok := ctx.Storage.(storm.PairwiseTransformer); ok {
		p.pairwiseTransformer = pt
	}
	if sr, ok := ctx.Storage.(storm.ClientSessionRecorder); ok {
		p.sessionRecorder = sr
	}
	p.allowPrivateIPs = ctx.AllowPrivateIPs
	p.skipTLSCertVerify = ctx.SkipTLSCertVerify
	return p
}

// NewWithConfig creates a new Token plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.DevicePollInterval == 0 {
		cfg.DevicePollInterval = 5 * time.Second
	}
	return &Plugin{
		tokenStore:         cfg.TokenStore,
		clientStore:        cfg.ClientStore,
		authStore:          cfg.AuthStore,
		cibaStore:          cfg.CIBAStore,
		crypto:             cfg.Crypto,
		keyStore:           cfg.KeyStore,
		decoder:            cfg.Decoder,
		logger:             cfg.Logger,
		devicePollInterval: cfg.DevicePollInterval,
		requireDPoP:        cfg.RequireDPoP,
		requireMtls:        cfg.RequireMtls,
		sessionRecorder:    cfg.SessionRecorder,
	}
}

// init self-registers the token plugin in the global registry.
func init() {
	storm.RegisterPlugin("token", storm.PriorityToken, func(ctx *storm.PluginContext) storm.Plugin {
		return New(ctx)
	})
}

// Category returns CategoryCore — token is a required OAuth 2.0 endpoint.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryCore }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string {
	return []string{"TokenStore", "AuthStore", "ClientStore", "KeyStore"}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "token" }

// SetDPoPNonceSender sets the DPoP nonce sender for server-provided nonces.
// Called by the Engine during Build when both token and dpop plugins are present.
func (p *Plugin) SetDPoPNonceSender(sender DPoPNonceSender) {
	p.dpopNonceSender = sender
}

// Register installs the POST /token route.
func (p *Plugin) Register(r chi.Router) {
	r.Post("/token", p.handleToken)
}

// Contribute returns the discovery fields for the token endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.TokenEndpoint = shared.EndpointURL(ctx, protocol.NewEndpoint("/token"))
	cfg.GrantTypesSupported = append(cfg.GrantTypesSupported,
		string(protocol.GrantTypeClientCredentials),
		string(protocol.GrantTypeRefreshToken),
		string(protocol.GrantTypeBearer),
		string(protocol.GrantTypeTokenExchange),
	)
	cfg.TokenEndpointAuthMethodsSupported = append(cfg.TokenEndpointAuthMethodsSupported,
		string(protocol.AuthMethodNone),
		string(protocol.AuthMethodBasic),
		string(protocol.AuthMethodPost),
		string(protocol.AuthMethodPrivateKeyJWT),
	)

	// ID Token encryption support
	cfg.IDTokenEncryptionAlgValuesSupported = []string{
		"RSA-OAEP", "RSA-OAEP-256",
		"A128KW", "A192KW", "A256KW",
		"A128GCMKW", "A192GCMKW", "A256GCMKW",
		"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
		"dir",
	}
	cfg.IDTokenEncryptionEncValuesSupported = []string{
		"A256GCM", "A192GCM", "A128GCM",
		"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
	}
}

// --- main handler ---

func (p *Plugin) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err))
		return
	}

	// DEBUG: dump all form keys
	formKeys := make([]string, 0, len(r.Form))
	for k := range r.Form {
		formKeys = append(formKeys, k)
	}
	slog.Info("[DEBUG] token handleToken", "grant_type", r.Form.Get("grant_type"), "form_keys", formKeys, "assertion_type", r.Form.Get("client_assertion_type"), "has_assertion", r.Form.Get("client_assertion") != "", "has_dpop", r.Header.Get("DPoP") != "", "global_requireDPoP", p.requireDPoP, "global_requireMtls", p.requireMtls)

	// Sender-constraining is validated after the client is authenticated so that
	// per-client configuration (via shared.SenderConstrainingProvider) can override
	// the plugin-wide defaults. This avoids a global-only gate rejecting clients
	// that do not require DPoP/mTLS.

	// RFC 7523 §2.2 / OIDC Core §9: client_assertion takes precedence
	if assertionType := r.Form.Get("client_assertion_type"); assertionType == protocol.ClientAssertionTypeJWTAssertion {
		assertion := r.Form.Get("client_assertion")
		if assertion == "" {
			slog.Warn("[DEBUG] token client_assertion missing")
			tokenError(w, r, protocol.ErrInvalidClient().WithDescription("client_assertion is missing"))
			return
		}
		client, err := p.authenticatePrivateKeyJWT(r, assertion)
		if err != nil {
			slog.Warn("[DEBUG] token authenticatePrivateKeyJWT failed", "error", err)
			tokenError(w, r, err)
			return
		}
		slog.Info("[DEBUG] token client authenticated via assertion", "client_id", client.GetID())
		r = r.WithContext(shared.ContextWithAuthenticatedClient(r.Context(), client))
	}

	// FAPI 2.0: sender-constrained token check for private_key_jwt clients.
	// For other auth methods, the check is performed in authenticateClient.
	if c := shared.AuthenticatedClientFromContext(r.Context()); c != nil {
		rd, rm := p.requireDPoP, p.requireMtls
		if sc, ok := c.(shared.SenderConstrainingProvider); ok {
			rd, rm = sc.RequireDPoP(), sc.RequireMtls()
		}
		slog.Info("[DEBUG] token handleToken post-auth sender-constraining", "client_id", c.GetID(), "requireDPoP", rd, "requireMtls", rm, "has_dpop_header", r.Header.Get("DPoP") != "", "has_client_cert", shared.ClientCertFromContext(r.Context()) != nil)
		if err := shared.ValidateSenderConstraining(c, p.requireDPoP, p.requireMtls, r); err != nil {
			tokenError(w, r, err)
			return
		}
	}

	grantType := r.Form.Get("grant_type")
	if grantType == "" {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("grant_type is missing"))
		return
	}

	switch protocol.GrantType(grantType) {
	case protocol.GrantTypeCode:
		p.handleAuthorizationCode(w, r)
	case protocol.GrantTypeRefreshToken:
		p.handleRefreshToken(w, r)
	case protocol.GrantTypeClientCredentials:
		p.handleClientCredentials(w, r)
	case protocol.GrantTypeBearer:
		p.handleJWTProfile(w, r)
	case protocol.GrantTypeTokenExchange:
		p.handleTokenExchange(w, r)
	case protocol.GrantTypeDeviceCode:
		p.handleDeviceCode(w, r)
	case protocol.GrantTypeCIBA:
		p.handleCIBA(w, r)
	default:
		tokenError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("unsupported grant_type: %s", grantType))
	}
}

// --- authorization_code grant (RFC 6749 §4.1.3, OIDC Core §3.1.3.1) ---

func (p *Plugin) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	ctx, span := shared.TracerSpan(r.Context(), p.tracer, "token.authorization_code")
	defer span.End()
	r = r.WithContext(ctx)

	tokenReq, err := parseAccessTokenRequest(r.Form, p.decoder)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cannot parse token request")
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("cannot parse token request").WithParent(err))
		return
	}

	if tokenReq.Code == "" {
		span.SetStatus(codes.Error, "code is missing")
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("code is missing"))
		return
	}

	span.SetAttributes(
		attribute.String("client_id", tokenReq.ClientID),
		attribute.String("grant_type", "authorization_code"),
	)

	authReq, err := p.authStore.AuthRequestByCode(r.Context(), tokenReq.Code)
	if err != nil {
		if detector, ok := p.authStore.(storm.CodeReuseDetector); ok {
			detector.RevokeTokensForUsedCode(tokenReq.Code)
		}
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("invalid code").WithParent(err))
		return
	}

	// FAPI 2.0: check sender-constraining requirements for the code's client
	// before authenticating the client. This ensures that a request missing the
	// holder-of-key mechanism (e.g. no DPoP proof) returns an invalid_request/
	// invalid_grant/invalid_dpop_proof error rather than invalid_client, even
	// when the client authentication parameters are absent or malformed.
	codeClient, err := p.clientStore.GetClientByClientID(r.Context(), authReq.GetClientID())
	if err == nil {
		if err := shared.ValidateSenderConstraining(codeClient, p.requireDPoP, p.requireMtls, r); err != nil {
			tokenError(w, r, err)
			return
		}
	}

	client, err := p.authenticateClient(r, tokenReq.ClientID, tokenReq.ClientSecret)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	if client.GetID() != authReq.GetClientID() {
		tokenError(w, r, protocol.ErrInvalidGrant())
		return
	}

	if !validateGrantType(client, protocol.GrantTypeCode) {
		tokenError(w, r, protocol.ErrUnauthorizedClient().WithDescription("client missing grant_type authorization_code"))
		return
	}

	if tokenReq.RedirectURI != "" && tokenReq.RedirectURI != authReq.GetRedirectURI() {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("redirect_uri does not correspond"))
		return
	}
	// RFC 6749 §4.1.3: redirect_uri is REQUIRED in the token request if it was
	// included in the authorization request. This prevents an attacker who obtains
	// an authorization code from redeeming it at a different redirect_uri.
	if authReq.GetRedirectURI() != "" && tokenReq.RedirectURI == "" {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("redirect_uri required (was present in authorization request)"))
		return
	}

	if err := verifyPKCE(authReq, tokenReq.CodeVerifier); err != nil {
		tokenError(w, r, err)
		return
	}

	// DPoP authorization code binding (RFC 9449 §7.1)
	if err := verifyDPoPCodeBinding(r.Context(), p.authStore, authReq.GetID(), r); err != nil {
		tokenError(w, r, err)
		return
	}

	// RFC 8707: merge resource indicator values into the token request's audience.
	// If the auth request stored resource values, wrap it so GetAudience()
	// includes them, ensuring the access token's aud claim is correct.
	tokenRequest := storm.TokenRequest(authReq)
	if ri, ok := authReq.(storm.ResourceIndicator); ok {
		if resources := ri.GetResources(); len(resources) > 0 {
			tokenRequest = &resourceAwareRequest{TokenRequest: authReq, resources: resources}
		}
	}

	resp, tokenID, err := p.createTokenResponseFromTokenRequest(r.Context(), tokenRequest, client, tokenResponseOpts{
		IssueRefresh: true,
		Code:         tokenReq.Code,
	})
	if err != nil {
		tokenError(w, r, err)
		return
	}

	if detector, ok := p.authStore.(storm.CodeReuseDetector); ok && tokenID != "" {
		detector.TrackTokenForAuthRequest(authReq.GetID(), tokenID)
	}

	_ = p.authStore.DeleteAuthRequest(r.Context(), authReq.GetID())

	p.writeTokenResponse(w, r, resp)
}

// verifyDPoPCodeBinding verifies the DPoP authorization code binding (RFC 9449 §7.1).
// If the authorization request included a dpop_jkt parameter, the token request
// must include a DPoP proof with a matching JWK thumbprint.
func verifyDPoPCodeBinding(ctx context.Context, authStore storm.AuthStore, authRequestID string, r *http.Request) error {
	// Check if auth store supports DPoP code binding
	bindingStore, ok := authStore.(storm.DPoPCodeBindingStore)
	if !ok {
		return nil // no binding support
	}

	// Get stored JKT for this auth request
	storedJKT, err := bindingStore.GetAuthRequestDPoPJKT(ctx, authRequestID)
	if err != nil || storedJKT == "" {
		return nil // no binding required
	}

	// Get DPoP proof from context
	proof := shared.DPoPFromContext(ctx)
	if proof == nil {
		return protocol.ErrInvalidGrant().WithDescription("DPoP proof required for code binding")
	}

	// Verify JKT matches
	if proof.JWKThumbprint() != storedJKT {
		return protocol.ErrInvalidGrant().WithDescription("DPoP proof does not match code binding")
	}

	return nil
}

// --- refresh_token grant (RFC 6749 §6) ---

func (p *Plugin) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	tokenReq, err := parseRefreshTokenRequest(r.Form, p.decoder)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("cannot parse refresh token request").WithParent(err))
		return
	}

	if tokenReq.RefreshToken == "" {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("refresh_token is missing"))
		return
	}

	// FAPI 2.0: look up the refresh token's client and enforce sender-constraining
	// before authenticating the client. This ensures a missing holder-of-key proof
	// is reported as invalid_request/invalid_grant/invalid_dpop_proof rather than
	// invalid_client when client authentication parameters are absent or malformed.
	refreshReq, err := p.tokenStore.TokenRequestByRefreshToken(r.Context(), tokenReq.RefreshToken)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidGrant().WithParent(err))
		return
	}

	rtClient, err := p.clientStore.GetClientByClientID(r.Context(), refreshReq.GetClientID())
	if err == nil {
		if err := shared.ValidateSenderConstraining(rtClient, p.requireDPoP, p.requireMtls, r); err != nil {
			tokenError(w, r, err)
			return
		}
	}

	client, err := p.authenticateClient(r, tokenReq.ClientID, tokenReq.ClientSecret)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	if !validateGrantType(client, protocol.GrantTypeRefreshToken) {
		tokenError(w, r, protocol.ErrUnauthorizedClient())
		return
	}

	if client.GetID() != refreshReq.GetClientID() {
		tokenError(w, r, protocol.ErrInvalidGrant())
		return
	}

	if err := validateRefreshScopes(tokenReq.Scopes, refreshReq); err != nil {
		tokenError(w, r, err)
		return
	}

	// RFC 9449 §7.2 / FAPI 2.0 Security Profile: DPoP-bound refresh token
	// proof-of-possession. The refresh token was issued with a cnf.jkt binding.
	// For confidential clients the conformance suite rotates the DPoP key on
	// refresh (see RefreshTokenRequestSteps), so we only require that a valid
	// DPoP proof is presented; the new access/refresh tokens will be bound to
	// the new key. For public clients RFC 9449 requires the same key to be used,
	// but FAPI 2.0 only exercises confidential clients.
	storedJKT := refreshReq.GetDPoPJKT()
	if storedJKT != "" {
		proof := shared.DPoPFromContext(r.Context())
		if proof == nil {
			tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("DPoP proof required for DPoP-bound refresh token"))
			return
		}
	}

	resp, _, err := p.createTokenResponseFromTokenRequest(r.Context(), refreshReq, client, tokenResponseOpts{
		IssueRefresh:        true,
		CurrentRefreshToken: "", // Don't pass old RT — OIDC conformance tests may not parse the new one from the response.
	})
	if err != nil {
		tokenError(w, r, err)
		return
	}

	p.writeTokenResponse(w, r, resp)
}

// --- client_credentials grant (RFC 6749 §4.4) ---

func (p *Plugin) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	tokenReq, err := parseClientCredentialsRequest(r.Form, p.decoder)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("cannot parse client credentials request").WithParent(err))
		return
	}

	client, err := p.authenticateClient(r, tokenReq.ClientID, tokenReq.ClientSecret)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	if !validateGrantType(client, protocol.GrantTypeClientCredentials) {
		tokenError(w, r, protocol.ErrUnauthorizedClient())
		return
	}

	ccs, ok := p.tokenStore.(clientCredentialsStore)
	if !ok {
		tokenError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("client_credentials not supported"))
		return
	}

	tokenRequest, err := ccs.ClientCredentialsTokenRequest(r.Context(), client.GetID(), tokenReq.Scope)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	resp, err := p.createClientCredentialsResponse(r.Context(), tokenRequest, client)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	p.writeTokenResponse(w, r, resp)
}

// --- jwt-bearer grant (RFC 7523 §2.1) ---

// handleJWTProfile implements the JWT Bearer Grant (RFC 7523 §2.1).
//
// The client sends a signed JWT assertion to obtain an access token.
// The JWT must contain:
//   - iss: client_id
//   - sub: the user subject to authorize
//   - aud: the token endpoint or issuer URL
//   - exp: expiration time (max 5 minutes)
//   - iat: issued-at time
//
// The client must implement storm.ClientJWKSProvider to provide its
// public keys for signature verification.
func (p *Plugin) handleJWTProfile(w http.ResponseWriter, r *http.Request) {
	assertion := r.Form.Get("assertion")
	if assertion == "" {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("assertion is missing"))
		return
	}

	// Parse JWT payload to extract claims
	request := new(protocol.JWTTokenRequest)
	if _, err := protocol.ParseToken(assertion, request); err != nil {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("invalid assertion: %s", err.Error()))
		return
	}

	// Validate required claims
	if request.Issuer == "" {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("assertion missing iss claim"))
		return
	}
	if request.Subject == "" {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("assertion missing sub claim"))
		return
	}

	// Look up client by iss (client_id)
	client, err := p.clientStore.GetClientByClientID(r.Context(), request.Issuer)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("unknown client: %s", request.Issuer))
		return
	}

	// Check client has jwt-bearer grant type
	if !validateGrantType(client, protocol.GrantTypeBearer) {
		tokenError(w, r, protocol.ErrUnauthorizedClient().WithDescription("client missing grant_type jwt-bearer"))
		return
	}

	// Get client's JWKS for signature verification
	jwksProvider, ok := client.(storm.ClientJWKSProvider)
	if !ok {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("client does not support JWT bearer grant (no JWKS)"))
		return
	}
	keys := jwksProvider.ClientJWKS()
	if len(keys) == 0 {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("client has no signing keys"))
		return
	}

	// Parse JWS header to get kid and alg
	jwsMsg, err := jws.Parse([]byte(assertion))
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("invalid JWS: %s", err.Error()))
		return
	}
	keyID, alg := protocol.GetKeyIDAndAlg(jwsMsg)

	// Find matching key
	key, err := protocol.FindMatchingKey(keyID, protocol.KeyUseSignature, alg, keys...)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("no matching key found for kid=%q alg=%s", keyID, alg))
		return
	}

	// Verify signature
	jwaAlg, ok := jwa.LookupSignatureAlgorithm(alg)
	if !ok {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("unsupported signing algorithm: %s", alg))
		return
	}
	_, err = jws.Verify([]byte(assertion), jws.WithKey(jwaAlg, key))
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("signature verification failed: %s", err.Error()))
		return
	}

	// Verify aud contains the issuer URL (RFC 7523 §2.1)
	issuer := shared.IssuerFromContext(r.Context())
	if !slices.Contains(request.Audience, issuer) {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("audience must contain issuer %q", issuer))
		return
	}

	// Verify exp (max 5 minutes per RFC 7523 §2.1)
	if request.ExpiresAt == 0 {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("assertion missing exp claim"))
		return
	}
	expTime := request.ExpiresAt.AsTime()
	if expTime.Before(time.Now().UTC()) {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("assertion expired"))
		return
	}
	if expTime.After(time.Now().UTC().Add(5 * time.Minute)) {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("assertion exp too far in the future (max 5 minutes)"))
		return
	}

	// Verify iat is not in the future
	if request.IssuedAt != 0 && request.IssuedAt.AsTime().After(time.Now().UTC().Add(10*time.Second)) {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("assertion iat is in the future"))
		return
	}

	// Parse scopes from form (optional)
	var scopes []string
	if scopeStr := r.Form.Get("scope"); scopeStr != "" {
		scopes = strings.Split(scopeStr, " ")
	}

	// Create token request
	tokenRequest := &jwtBearerTokenRequest{
		subject:  request.Subject,
		clientID: request.Issuer,
		scopes:   scopes,
		audience: request.Audience,
	}

	resp, _, err := p.createTokenResponseFromTokenRequest(r.Context(), tokenRequest, client, tokenResponseOpts{
		IssueRefresh: false, // JWT Bearer Grant does not issue refresh tokens per RFC 7523
	})
	if err != nil {
		tokenError(w, r, err)
		return
	}

	p.writeTokenResponse(w, r, resp)
}

// --- token exchange grant (RFC 8693) ---

func (p *Plugin) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	req := new(protocol.TokenExchangeRequest)
	if err := p.decoder.Decode(req, r.Form); err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("cannot parse token exchange request").WithParent(err))
		return
	}

	if req.SubjectToken == "" {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("subject_token missing"))
		return
	}
	if req.SubjectTokenType == "" {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("subject_token_type missing"))
		return
	}

	clientID, clientSecret := "", ""
	if id, secret, ok := r.BasicAuth(); ok {
		var err error
		clientID, err = url.QueryUnescape(id)
		if err != nil {
			tokenError(w, r, protocol.ErrInvalidClient().WithDescription("invalid basic auth header"))
			return
		}
		clientSecret, err = url.QueryUnescape(secret)
		if err != nil {
			tokenError(w, r, protocol.ErrInvalidClient().WithDescription("invalid basic auth header"))
			return
		}
	}

	client, err := p.authenticateClient(r, clientID, clientSecret)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	if !validateGrantType(client, protocol.GrantTypeTokenExchange) {
		tokenError(w, r, protocol.ErrUnauthorizedClient())
		return
	}

	subject, subjectTokenID, err := p.resolveExchangeToken(r.Context(), req.SubjectToken, req.SubjectTokenType)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("subject_token is invalid").WithParent(err))
		return
	}

	teStore, ok := p.tokenStore.(storm.TokenExchangeStore)
	if !ok {
		tokenError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("token exchange not supported by storage"))
		return
	}

	teReq := &tokenExchangeRequest{
		subject:               subject,
		subjectTokenIDOrToken: subjectTokenID,
		subjectTokenType:      req.SubjectTokenType,
		clientID:              client.GetID(),
		audience:              req.Audience,
		scopes:                req.Scopes,
		requestedTokenType:    req.RequestedTokenType,
	}

	if teReq.requestedTokenType == "" {
		teReq.requestedTokenType = protocol.AccessTokenType
	}

	if err := teStore.ValidateTokenExchangeRequest(r.Context(), teReq); err != nil {
		tokenError(w, r, err)
		return
	}

	_ = teStore.CreateTokenExchangeRequest(r.Context(), teReq)

	accessToken, _, _, validity, err := p.createAccessToken(r.Context(), teReq, client, false, "", nil)
	if err != nil {
		tokenError(w, r, protocol.ErrServerError().WithParent(err))
		return
	}

	resp := &protocol.TokenExchangeResponse{
		AccessToken:     accessToken,
		IssuedTokenType: teReq.requestedTokenType,
		TokenType:       protocol.BearerToken,
		ExpiresIn:       uint64(validity.Seconds()),
		Scopes:          teReq.scopes,
	}

	p.writeTokenResponse(w, r, resp)
}

// resolveExchangeToken resolves a subject_token to (subject, tokenIDOrToken).
func (p *Plugin) resolveExchangeToken(ctx context.Context, token string, tokenType protocol.TokenType) (subject, tokenIDOrToken string, err error) {
	switch tokenType {
	case protocol.RefreshTokenType:
		tokenRequest, err := p.tokenStore.TokenRequestByRefreshToken(ctx, token)
		if err != nil {
			return "", "", err
		}
		return tokenRequest.GetSubject(), token, nil
	case protocol.AccessTokenType:
		tokenID, subject, ok := storm.ResolveToken(ctx, p.crypto, p.keyStore, shared.IssuerFromContext(ctx), token)
		if !ok {
			return "", "", fmt.Errorf("invalid access token")
		}
		return subject, tokenID, nil
	default:
		return "", "", fmt.Errorf("unsupported subject_token_type: %s", tokenType)
	}
}

// --- device_code grant (RFC 8628 §3.4) ---

func (p *Plugin) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if p.deviceAuthStore == nil {
		tokenError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("device_code grant not supported by storage"))
		return
	}

	if err := r.ParseForm(); err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err))
		return
	}

	deviceCode := r.Form.Get("device_code")
	clientID := r.Form.Get("client_id")
	if deviceCode == "" {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("device_code is required"))
		return
	}

	client, err := p.authenticateClient(r, clientID, r.Form.Get("client_secret"))
	if err != nil {
		tokenError(w, r, err)
		return
	}

	if !validateGrantType(client, protocol.GrantTypeDeviceCode) {
		tokenError(w, r, protocol.ErrUnauthorizedClient())
		return
	}

	state, err := p.deviceAuthStore.GetDeviceAuthorizationState(r.Context(), clientID, deviceCode)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("unknown device_code"))
		return
	}

	if time.Now().After(state.Expires) {
		tokenError(w, r, protocol.ErrExpiredDeviceCode())
		return
	}

	if state.Denied {
		tokenError(w, r, protocol.ErrAccessDenied())
		return
	}

	// RFC 8628 §3.4: slow_down detection
	// If the client polls faster than the interval, return slow_down error
	// and increase the interval by 5 seconds for all subsequent requests.
	now := time.Now()
	interval := p.devicePollInterval
	if state.Interval > 0 {
		interval = time.Duration(state.Interval) * time.Second
	}

	if !state.LastPoll.IsZero() {
		elapsed := now.Sub(state.LastPoll)
		if elapsed < interval {
			if err := p.deviceAuthStore.UpdateDeviceAuthorizationInterval(r.Context(), clientID, deviceCode, 5); err != nil {
				p.logger.Warn("failed to increase device poll interval", "error", err)
			}
			tokenError(w, r, protocol.ErrSlowDown())
			return
		}
	}

	// Update last poll time
	if err := p.deviceAuthStore.UpdateDeviceAuthorizationPoll(r.Context(), clientID, deviceCode, now); err != nil {
		p.logger.Warn("failed to update device poll time", "error", err)
	}

	if !state.Done {
		tokenError(w, r, protocol.ErrAuthorizationPending())
		return
	}

	req := &deviceTokenRequest{
		subject:  state.Subject,
		clientID: clientID,
		scopes:   state.Scopes,
	}

	resp, _, err := p.createTokenResponseFromTokenRequest(r.Context(), req, client, tokenResponseOpts{
		IssueRefresh: true,
	})
	if err != nil {
		tokenError(w, r, err)
		return
	}

	p.writeTokenResponse(w, r, resp)
}

// --- ciba grant (CIBA Core 1.0 §8) ---

func (p *Plugin) handleCIBA(w http.ResponseWriter, r *http.Request) {
	if p.cibaStore == nil {
		tokenError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("ciba grant not supported by storage"))
		return
	}

	if err := r.ParseForm(); err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err))
		return
	}

	authReqID := r.Form.Get("auth_req_id")
	if authReqID == "" {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("auth_req_id is required"))
		return
	}

	// CIBA Core 1.0 §8: client authentication is required for CIBA token requests
	// The authentication method depends on the client's registered token_endpoint_auth_method:
	// - private_key_jwt: requires client_assertion (already handled by handleToken)
	// - tls_client_auth: accepts mTLS client certificate

	// If the client was already authenticated via client_assertion (private_key_jwt)
	// in handleToken, reuse that identity instead of re-authenticating.
	var client storm.Client
	if c := shared.AuthenticatedClientFromContext(r.Context()); c != nil {
		client = c.(storm.Client)
		// Verify the form client_id matches the authenticated client (if provided)
		if formClientID := r.Form.Get("client_id"); formClientID != "" && formClientID != client.GetID() {
			tokenError(w, r, protocol.ErrInvalidClient().WithDescription("client_id does not match authenticated client"))
			return
		}
	} else {
		// No client_assertion was provided — check client's registered auth method
		clientID := r.Form.Get("client_id")
		if clientID == "" {
			tokenError(w, r, protocol.ErrInvalidClient().WithDescription("client_id is required when client_assertion is not provided"))
			return
		}
		c, err := p.clientStore.GetClientByClientID(r.Context(), clientID)
		if err != nil {
			tokenError(w, r, protocol.ErrInvalidClient().WithParent(err))
			return
		}
		cert := shared.ClientCertFromContext(r.Context())
		if c.AuthMethod() == protocol.AuthMethodTLSClientAuth {
			// tls_client_auth: require mTLS certificate
			if cert == nil {
				tokenError(w, r, protocol.ErrInvalidClient().WithDescription("mTLS client certificate is required for tls_client_auth client"))
				return
			}
			// Optional: client-level certificate identity validation (RFC 8705 §2.1)
			if v, ok := c.(shared.ClientCertBoundAuthenticator); ok {
				if err := v.ValidateClientCert(cert, clientID); err != nil {
					tokenError(w, r, protocol.ErrInvalidClient().WithParent(err))
					return
				}
			}
			// Sender-constraining check
			if err := shared.ValidateSenderConstraining(c, p.requireDPoP, p.requireMtls, r); err != nil {
				tokenError(w, r, err)
				return
			}
		} else if c.AuthMethod() == protocol.AuthMethodPrivateKeyJWT {
			// private_key_jwt: require client_assertion, no mTLS fallback
			tokenError(w, r, protocol.ErrInvalidClient().WithDescription("client_assertion is required for private_key_jwt client"))
			return
		} else {
			tokenError(w, r, protocol.ErrInvalidClient().WithDescription("unsupported auth method for CIBA"))
			return
		}
		client = c
	}

	if !validateGrantType(client, protocol.GrantTypeCIBA) {
		tokenError(w, r, protocol.ErrUnauthorizedClient())
		return
	}

	cibaReq, err := p.cibaStore.GetCIBARequestByAuthReqID(r.Context(), authReqID)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("unknown auth_req_id"))
		return
	}

	// CIBA Core 1.0 §8.1: verify the client owns this request.
	// ensure-wrong-auth-req-id: authenticated as client 2, auth_req_id from client 1
	//   → form client_id matches auth client → ownership check → invalid_grant
	// ensure-wrong-client-id: form client_id ≠ auth client → invalid_client (caught above)
	if cibaReq.ClientID != client.GetID() {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("auth_req_id does not belong to this client"))
		return
	}

	// Check expiration
	if time.Now().After(cibaReq.ExpiresAt) {
		tokenError(w, r, protocol.ErrExpiredDeviceCode().WithDescription("The auth_req_id has expired."))
		return
	}

	// Check status first — denied/approved requests should not trigger slow_down.
	switch cibaReq.Status {
	case protocol.CIBAStatusDenied:
		tokenError(w, r, protocol.ErrAccessDenied())
		return
	case protocol.CIBAStatusConsumed:
		// CIBA Core 1.0: auth_req_id cannot be reused after token issuance.
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("auth_req_id has already been consumed"))
		return
	case protocol.CIBAStatusApproved:
		// Continue to token creation
	case protocol.CIBAStatusPending:
		// CIBA Core 1.0 §10.1: slow_down detection
		// If the client polls faster than the interval, return slow_down error
		// and increase the interval by 5 seconds for all subsequent requests.
		now := time.Now()
		interval := p.devicePollInterval // reuse the same default interval
		if cibaReq.Interval > 0 {
			interval = time.Duration(cibaReq.Interval) * time.Second
		}

		if !cibaReq.LastPoll.IsZero() {
			elapsed := now.Sub(cibaReq.LastPoll)
			if elapsed < interval {
				if err := p.cibaStore.UpdateCIBAInterval(r.Context(), authReqID, 5); err != nil {
					p.logger.Warn("failed to increase CIBA poll interval", "error", err)
				}
				tokenError(w, r, protocol.ErrSlowDown())
				return
			}
		}

		// Update last poll time
		if err := p.cibaStore.UpdateCIBAPoll(r.Context(), authReqID, now); err != nil {
			p.logger.Warn("failed to update CIBA poll time", "error", err)
		}

		tokenError(w, r, protocol.ErrAuthorizationPending())
		return
	default:
		tokenError(w, r, protocol.ErrServerError().WithDescription("unexpected CIBA request status"))
		return
	}

	req := &cibaTokenRequest{
		subject:  cibaReq.Subject,
		clientID: client.GetID(),
		scopes:   cibaReq.ApprovedScopes,
	}

	resp, _, err := p.createTokenResponseFromTokenRequest(r.Context(), req, client, tokenResponseOpts{
		IssueRefresh: true,
	})
	if err != nil {
		tokenError(w, r, err)
		return
	}

	// Mark the CIBA request as consumed to prevent reuse of auth_req_id.
	if err := p.cibaStore.UpdateCIBARequestStatus(r.Context(), authReqID, protocol.CIBAStatusConsumed, cibaReq.ApprovedScopes); err != nil {
		p.logger.Warn("failed to mark CIBA request as consumed", "error", err)
	}

	p.writeTokenResponse(w, r, resp)
}

// --- client authentication ---

func (p *Plugin) authenticateClient(r *http.Request, formClientID, formClientSecret string) (storm.Client, error) {
	// If the client was already authenticated via client_assertion (private_key_jwt),
	// return it directly — no need to re-authenticate.
	if c := shared.AuthenticatedClientFromContext(r.Context()); c != nil {
		slog.Info("[DEBUG] token authenticateClient: using pre-authenticated client", "client_id", c.GetID())
		return p.clientStore.GetClientByClientID(r.Context(), c.GetID())
	}

	clientID, clientSecret := formClientID, formClientSecret

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

	slog.Info("[DEBUG] token authenticateClient", "client_id", clientID, "has_secret", clientSecret != "", "auth_method", "from_context")

	if clientID == "" {
		slog.Warn("[DEBUG] token authenticateClient: client_id missing")
		return nil, protocol.ErrInvalidClient().WithDescription("client_id missing")
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		slog.Warn("[DEBUG] token authenticateClient: GetClientByClientID failed", "client_id", clientID, "error", err)
		return nil, protocol.ErrInvalidClient().WithParent(err)
	}

	// FAPI 2.0 / RFC 7523: private_key_jwt clients MUST authenticate via
	// client_assertion. If the client's registered auth method requires an
	// assertion but none was provided (i.e. the client is not in context),
	// check for mTLS client certificate as an alternative authentication
	// method (RFC 8705 §3, tls_client_auth). This allows the same client to
	// be tested with both private_key_jwt and mTLS client_auth_type variants.
	// For tls_client_auth the TLS layer has already validated the certificate
	// chain; we only need to verify that a client certificate is present.
	if client.AuthMethod() == protocol.AuthMethodPrivateKeyJWT {
		cert := shared.ClientCertFromContext(r.Context())
		if cert == nil {
			return nil, protocol.ErrInvalidClient().WithDescription("client_assertion required for private_key_jwt client")
		}
		slog.Info("[DEBUG] token authenticateClient: private_key_jwt client authenticated via mTLS tls_client_auth", "client_id", clientID, "cert_cn", cert.Subject.CommonName)
		// Sender-constraining check for mTLS-authenticated clients.
		if err := shared.ValidateSenderConstraining(client, p.requireDPoP, p.requireMtls, r); err != nil {
			return nil, err
		}
		return client, nil
	}

	if client.AuthMethod() != protocol.AuthMethodNone {
		if err := p.clientStore.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			slog.Warn("[DEBUG] token authenticateClient: AuthorizeClientIDSecret failed", "client_id", clientID, "error", err)
			return nil, err
		}
	}

	slog.Info("[DEBUG] token authenticateClient: success", "client_id", client.GetID(), "auth_method", client.AuthMethod())

	// FAPI 2.0: sender-constrained token check for non-private_key_jwt clients.
	if err := shared.ValidateSenderConstraining(client, p.requireDPoP, p.requireMtls, r); err != nil {
		return nil, err
	}

	return client, nil
}

// authenticatePrivateKeyJWT authenticates the client using a JWT assertion
// signed with the client's private key (RFC 7523 §2.2, OIDC Core §9).
func (p *Plugin) authenticatePrivateKeyJWT(r *http.Request, assertion string) (storm.Client, error) {
	issuer := shared.IssuerFromContext(r.Context())
	tokenEndpoint := shared.EndpointURL(r.Context(), protocol.NewEndpoint("/token"))
	bcAuthorizeEndpoint := shared.EndpointURL(r.Context(), protocol.NewEndpoint("/bc-authorize"))
	// Adapt storm.ClientStore.GetClientByClientID to shared.Client lookup.
	getClient := func(ctx context.Context, clientID string) (shared.Client, error) {
		return p.clientStore.GetClientByClientID(ctx, clientID)
	}
	getAudiences := func(client shared.Client) []string {
		// FAPI 2.0 §5.3.2.1: aud should be issuer URL.
		// OIDF conformance suite may send token endpoint URL or bc-authorize endpoint URL.
		return []string{issuer, tokenEndpoint, bcAuthorizeEndpoint}
	}
	client, err := shared.AuthenticatePrivateKeyJWT(r, getClient, assertion, getAudiences, p.skipTLSCertVerify, p.allowPrivateIPs)
	if err != nil {
		return nil, err
	}
	return client.(storm.Client), nil
}

// --- token creation ---

// tokenResponseOpts configures token response creation.
// Each grant type sets only the fields it needs.
type tokenResponseOpts struct {
	IssueRefresh        bool   // whether to issue a refresh token
	Code                string // authorization code (for c_hash in ID token)
	CurrentRefreshToken string // old refresh token to invalidate (rotation)
}

// senderConstrainingRequirements returns the effective DPoP/mTLS requirements
// for a client. Per-client configuration via shared.SenderConstrainingProvider
// takes precedence over the plugin-wide defaults.
func (p *Plugin) senderConstrainingRequirements(client storm.Client) (requireDPoP, requireMtls bool) {
	requireDPoP = p.requireDPoP
	requireMtls = p.requireMtls
	if sc, ok := client.(shared.SenderConstrainingProvider); ok {
		requireDPoP = sc.RequireDPoP()
		requireMtls = sc.RequireMtls()
	}
	return
}

// createTokenResponseFromTokenRequest creates a token response from any TokenRequest implementation.
func (p *Plugin) createTokenResponseFromTokenRequest(ctx context.Context, request storm.TokenRequest, client storm.Client, opts tokenResponseOpts) (*protocol.AccessTokenResponse, string, error) {
	// Apply pairwise subject transformation if applicable
	request = p.applyPairwise(request, client)

	// FAPI 2.0: reject requests without sender-constrained proof when required.
	// Must check before creating tokens so we fail fast without issuing tokens.
	// Per-client configuration takes precedence over plugin-wide defaults.
	requireDPoP, requireMtls := p.senderConstrainingRequirements(client)
	hasDPoP := shared.DPoPFromContext(ctx) != nil
	hasMtls := shared.ClientCertFromContext(ctx) != nil
	slog.Info("[DEBUG] token createTokenResponseFromTokenRequest sender-constraining", "client_id", client.GetID(), "requireDPoP", requireDPoP, "requireMtls", requireMtls, "has_dpop_ctx", hasDPoP, "has_mtls_ctx", hasMtls)
	// When both DPoP and mTLS are required (holder-of-key), either proof suffices.
	if requireDPoP && requireMtls {
		if !hasDPoP && !hasMtls {
			return nil, "", protocol.ErrInvalidRequest().WithDescription("holder-of-key proof required (FAPI 2.0 sender-constrained tokens)")
		}
	} else if requireDPoP && !hasDPoP {
		return nil, "", protocol.ErrInvalidRequest().WithDescription("DPoP proof required (FAPI 2.0 sender-constrained tokens)")
	} else if requireMtls && !hasMtls {
		return nil, "", protocol.ErrInvalidRequest().WithDescription("mTLS client certificate required (FAPI 2.0 sender-constrained tokens)")
	}

	// Resolve cnf claim from mTLS certificate and/or DPoP proof before token
	// creation so storage can bind refresh tokens at issuance time.
	cnf := shared.ResolveCNF(ctx)

	accessToken, tokenID, refreshToken, validity, err := p.createAccessToken(ctx, request, client, opts.IssueRefresh, opts.CurrentRefreshToken, cnf)
	if err != nil {
		return nil, "", err
	}

	// Only create ID token if the request includes "openid" scope (OIDC Core §2.1.3).
	// Plain OAuth requests without "openid" scope should not receive an ID token.
	var idToken string
	if slices.Contains(request.GetScopes(), protocol.ScopeOpenID) {
		idToken, err = p.createIDToken(ctx, request, client, accessToken, opts.Code)
		if err != nil {
			return nil, "", err
		}
	}

	// Determine token_type: DPoP-bound tokens use "DPoP" (RFC 9449 §7.1)
	tokenType := protocol.BearerToken
	if shared.DPoPFromContext(ctx) != nil {
		tokenType = "DPoP"
	}

	resp := &protocol.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   uint64(validity.Seconds()),
		Scope:       request.GetScopes(),
		IDToken:     idToken,
	}
	if opts.IssueRefresh && refreshToken != "" {
		resp.RefreshToken = refreshToken
	}

	// Record client session for back-channel logout tracking.
	// Only records when the storage implements ClientSessionRecorder
	// and the request provides a SID (authorization_code flow).
	if p.sessionRecorder != nil {
		if authReq, ok := request.(storm.AuthRequest); ok {
			if sid := authReq.GetSID(); sid != "" {
				p.sessionRecorder.RecordClientSession(request.GetSubject(), request.GetClientID(), sid)
			}
		}
	}

	return resp, tokenID, nil
}

// writeTokenResponse writes a successful token response with optional DPoP-Nonce header.
// RFC 9449 §8: the server MAY include a DPoP-Nonce header in 200 responses.
// Cache-Control: no-store is set by shared.JSONResponse per RFC 6749 §5.1.
func (p *Plugin) writeTokenResponse(w http.ResponseWriter, r *http.Request, resp any) {
	if p.dpopNonceSender != nil && shared.DPoPFromContext(r.Context()) != nil {
		p.dpopNonceSender.WriteNonceHeader(w)
	}
	shared.JSONResponse(w, resp, http.StatusOK)
}

// createIDToken creates and signs an ID token.
func (p *Plugin) createIDToken(ctx context.Context, request storm.TokenRequest, client storm.Client, accessToken string, code string) (string, error) {
	signingKey, err := p.keyStore.SigningKey(ctx)
	if err != nil {
		return "", err
	}

	// Determine the ID token signing algorithm:
	// 1. Client's explicit preference (OIDC Core §2: id_token_signed_response_alg)
	// 2. FAPI 2.0 default: PS256 (§5.4 requires PS256, ES256, or EdDSA)
	// 3. Server default (first signing key, typically RS256)
	preferredAlg := ""
	if algProvider, ok := client.(shared.IDTokenSignedResponseAlgProvider); ok {
		preferredAlg = algProvider.IDTokenSignedResponseAlg()
	}
	if preferredAlg == "" {
		if fapiClient, ok := client.(shared.FAPIProfileClient); ok && fapiClient.FAPIProfile() {
			preferredAlg = "PS256"
		}
	}
	if preferredAlg != "" {
		if algStore, ok := p.keyStore.(storm.SigningKeyByAlgProvider); ok {
			if algKey, err := algStore.SigningKeyByAlg(ctx, preferredAlg); err == nil {
				signingKey = algKey
			}
		}
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss": shared.IssuerFromContext(ctx),
		"sub": request.GetSubject(),
		"aud": request.GetClientID(),
		"iat": now.Unix(),
		"exp": now.Add(validIDTokenLifetime).Unix(),
	}
	if nonce := getNonce(request); nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		claims["at_hash"] = hashToken(accessToken, signingKey.Algorithm())
	}
	if code != "" {
		claims["c_hash"] = hashToken(code, signingKey.Algorithm())
	}
	if authReq, ok := request.(storm.AuthRequest); ok {
		if t := authReq.GetAuthTime(); !t.IsZero() {
			claims["auth_time"] = t.Unix()
		}
		if acr := authReq.GetACR(); acr != "" {
			claims["acr"] = acr
		}
		if amr := authReq.GetAMR(); len(amr) > 0 {
			claims["amr"] = amr
		}
		if sid := authReq.GetSID(); sid != "" {
			claims["sid"] = sid
		}
	}
	if ext, ok := request.(idTokenClaimsExtender); ok {
		for k, v := range ext.ExtraIDTokenClaims() {
			if _, exists := claims[k]; !exists {
				claims[k] = v
			}
		}
	}
	if len(request.GetAudience()) > 1 {
		claims["azp"] = request.GetClientID()
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	var signed string
	if gmKey, ok := signingKey.(storm.GMSigningKey); ok {
		signed, err = gmKey.GMSigner().Sign(payload)
		if err != nil {
			return "", err
		}
	} else {
		signed, err = crypto.SignJWS(payload, signingKey.Key())
		if err != nil {
			return "", fmt.Errorf("failed to sign ID token: %w", err)
		}
	}

	if encClient, ok := client.(idTokenEncryptionClient); ok {
		alg, enc := encClient.IDTokenEncryptionAlg(), encClient.IDTokenEncryptionEnc()
		if alg != "" && enc != "" {
			encrypted, err := encryptIDToken(signed, client, p.crypto, alg, enc)
			if err != nil {
				return "", fmt.Errorf("failed to encrypt ID token: %w", err)
			}
			return encrypted, nil
		}
	}

	return signed, nil
}

// createAccessToken creates an access token, optionally with a refresh token.
// currentRefreshToken: if non-empty, the old refresh token to invalidate (rotation).
// cnf: sender-constraining confirmation claim (may be nil).
func (p *Plugin) createAccessToken(ctx context.Context, request storm.TokenRequest, client storm.Client, issueRefresh bool, currentRefreshToken string, cnf map[string]any) (encryptedToken string, tokenID string, refreshToken string, validity time.Duration, err error) {
	// Refresh token 颁发条件：
	//   1. 调用方要求颁发（issueRefresh=true）
	//   2. client 声明了 refresh_token grant type
	// 对于 authorization_code grant：只有 response_type 含 code 时 issueRefresh 才为 true
	// 对于 refresh_token grant：始终为 true（刷新后必须返回新 refresh_token）
	needsRefresh := issueRefresh && validateGrantType(client, protocol.GrantTypeRefreshToken)

	var expiration time.Time
	if needsRefresh {
		tokenID, refreshToken, expiration, err = p.tokenStore.CreateAccessAndRefreshTokens(ctx, request, currentRefreshToken, cnf)
	} else {
		tokenID, expiration, err = p.tokenStore.CreateAccessToken(ctx, request, cnf)
	}
	if err != nil {
		return "", "", "", 0, err
	}

	plaintext := []byte(tokenID + ":" + request.GetSubject())
	encrypted, err := p.crypto.Encrypt(ctx, plaintext)
	if err != nil {
		return "", "", "", 0, err
	}

	validity = expiration.Sub(time.Now().UTC())
	encryptedToken = base64.RawURLEncoding.EncodeToString(encrypted)
	return encryptedToken, tokenID, refreshToken, validity, nil
}

// createClientCredentialsResponse creates a token response for client_credentials grant.
func (p *Plugin) createClientCredentialsResponse(ctx context.Context, tokenRequest storm.TokenRequest, client storm.Client) (*protocol.AccessTokenResponse, error) {
	// FAPI 2.0: reject requests without sender-constrained proof when required.
	// Per-client configuration takes precedence over plugin-wide defaults.
	requireDPoP, requireMtls := p.senderConstrainingRequirements(client)
	hasDPoP := shared.DPoPFromContext(ctx) != nil
	hasMtls := shared.ClientCertFromContext(ctx) != nil
	// When both DPoP and mTLS are required (holder-of-key), either proof suffices.
	if requireDPoP && requireMtls {
		if !hasDPoP && !hasMtls {
			return nil, protocol.ErrInvalidRequest().WithDescription("holder-of-key proof required (FAPI 2.0 sender-constrained tokens)")
		}
	} else if requireDPoP && !hasDPoP {
		return nil, protocol.ErrInvalidRequest().WithDescription("DPoP proof required (FAPI 2.0 sender-constrained tokens)")
	} else if requireMtls && !hasMtls {
		return nil, protocol.ErrInvalidRequest().WithDescription("mTLS client certificate required (FAPI 2.0 sender-constrained tokens)")
	}

	cnf := shared.ResolveCNF(ctx)

	accessToken, _, _, validity, err := p.createAccessToken(ctx, tokenRequest, client, false, "", cnf)
	if err != nil {
		return nil, err
	}

	// Determine token_type: DPoP-bound tokens use "DPoP" (RFC 9449 §7.1)
	tokenType := protocol.BearerToken
	if shared.DPoPFromContext(ctx) != nil {
		tokenType = "DPoP"
	}

	return &protocol.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   uint64(validity.Seconds()),
		Scope:       tokenRequest.GetScopes(),
	}, nil
}
