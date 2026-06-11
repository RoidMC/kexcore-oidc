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
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
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
	}
	if das, ok := ctx.Storage.(storm.DeviceAuthStore); ok {
		p.deviceAuthStore = das
	}
	if pt, ok := ctx.Storage.(storm.PairwiseTransformer); ok {
		p.pairwiseTransformer = pt
	}
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
		crypto:             cfg.Crypto,
		keyStore:           cfg.KeyStore,
		decoder:            cfg.Decoder,
		logger:             cfg.Logger,
		devicePollInterval: cfg.DevicePollInterval,
		requireDPoP:        cfg.RequireDPoP,
		requireMtls:        cfg.RequireMtls,
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
		"client_credentials", "refresh_token",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	)
	cfg.TokenEndpointAuthMethodsSupported = append(cfg.TokenEndpointAuthMethodsSupported,
		"client_secret_basic", "client_secret_post", "private_key_jwt",
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

	// RFC 7523 §2.2 / OIDC Core §9: client_assertion takes precedence
	if assertionType := r.Form.Get("client_assertion_type"); assertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		assertion := r.Form.Get("client_assertion")
		if assertion == "" {
			tokenError(w, r, protocol.ErrInvalidClient().WithDescription("client_assertion is missing"))
			return
		}
		client, err := p.authenticatePrivateKeyJWT(r, assertion)
		if err != nil {
			tokenError(w, r, err)
			return
		}
		r = r.WithContext(shared.ContextWithAuthenticatedClient(r.Context(), client))
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

	resp, tokenID, err := p.createTokenResponseFromTokenRequest(r.Context(), authReq, client, tokenResponseOpts{
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

	client, err := p.authenticateClient(r, tokenReq.ClientID, tokenReq.ClientSecret)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	if !validateGrantType(client, protocol.GrantTypeRefreshToken) {
		tokenError(w, r, protocol.ErrUnauthorizedClient())
		return
	}

	refreshReq, err := p.tokenStore.TokenRequestByRefreshToken(r.Context(), tokenReq.RefreshToken)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidGrant().WithParent(err))
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

	resp, _, err := p.createTokenResponseFromTokenRequest(r.Context(), refreshReq, client, tokenResponseOpts{
		IssueRefresh:        true,
		CurrentRefreshToken: tokenReq.RefreshToken,
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

	accessToken, _, _, validity, err := p.createAccessToken(r.Context(), teReq, client, false, "")
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

// --- client authentication ---

func (p *Plugin) authenticateClient(r *http.Request, formClientID, formClientSecret string) (storm.Client, error) {
	// If the client was already authenticated via client_assertion (private_key_jwt),
	// return it directly — no need to re-authenticate.
	if c := shared.AuthenticatedClientFromContext(r.Context()); c != nil {
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

	if clientID == "" {
		return nil, protocol.ErrInvalidClient().WithDescription("client_id missing")
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithParent(err)
	}

	if client.AuthMethod() != protocol.AuthMethodNone {
		if err := p.clientStore.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			return nil, err
		}
	}

	return client, nil
}

// authenticatePrivateKeyJWT authenticates the client using a JWT assertion
// signed with the client's private key (RFC 7523 §2.2, OIDC Core §9).
func (p *Plugin) authenticatePrivateKeyJWT(r *http.Request, assertion string) (storm.Client, error) {
	// Step 1: Parse the unverified JWT to extract iss (client_id).
	request := new(protocol.JWTTokenRequest)
	if _, err := protocol.ParseToken(assertion, request); err != nil {
		return nil, protocol.ErrInvalidClient().WithDescription("invalid client_assertion").WithParent(err)
	}
	if request.Issuer == "" {
		return nil, protocol.ErrInvalidClient().WithDescription("client_assertion missing iss claim")
	}

	// Step 2: Look up the client and verify it's configured for private_key_jwt.
	client, err := p.clientStore.GetClientByClientID(r.Context(), request.Issuer)
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithParent(err)
	}
	if client.AuthMethod() != protocol.AuthMethodPrivateKeyJWT {
		return nil, protocol.ErrInvalidClient().WithDescription("client not configured for private_key_jwt")
	}

	// Step 3: Get the client's keys for signature verification.
	// Prefer fetching fresh keys from jwks_uri if available (supports RP key rotation).
	clientKS, ok := client.(storm.ClientJWKSProvider)
	if !ok {
		return nil, protocol.ErrInvalidClient().WithDescription("client does not support private_key_jwt")
	}

	var clientKeys []jwk.Key
	if uriProvider, ok := client.(storm.ClientJWKSURIProvider); ok && uriProvider.ClientJWKSURI() != "" {
		// Fetch fresh keys from the client's jwks_uri
		fetchedKeys, err := fetchJWKSFromURI(uriProvider.ClientJWKSURI())
		if err != nil {
			slog.Default().Warn("failed to fetch client jwks_uri, falling back to cached keys", "error", err, "uri", uriProvider.ClientJWKSURI())
			clientKeys = clientKS.ClientJWKS()
		} else {
			clientKeys = fetchedKeys
		}
	} else {
		clientKeys = clientKS.ClientJWKS()
	}

	if len(clientKeys) == 0 {
		return nil, protocol.ErrInvalidClient().WithDescription("client has no registered keys")
	}

	// Step 4: Verify the assertion with the client's keys (not the OP's keyStore).
	issuer := shared.IssuerFromContext(r.Context())
	tokenEndpoint := shared.EndpointURL(r.Context(), protocol.NewEndpoint("/token"))
	allowedAudiences := []string{issuer, tokenEndpoint}
	if err := protocol.VerifyJWTAssertion(r.Context(), assertion, allowedAudiences, clientKeys, 10*time.Second); err != nil {
		return nil, protocol.ErrInvalidClient().WithDescription("invalid client_assertion").WithParent(err)
	}

	return client, nil
}

// fetchJWKSFromURI fetches and parses a JWKS from a remote URI.
func fetchJWKSFromURI(uri string) ([]jwk.Key, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(uri)
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

// --- token creation ---

// tokenResponseOpts configures token response creation.
// Each grant type sets only the fields it needs.
type tokenResponseOpts struct {
	IssueRefresh        bool   // whether to issue a refresh token
	Code                string // authorization code (for c_hash in ID token)
	CurrentRefreshToken string // old refresh token to invalidate (rotation)
}

// createTokenResponseFromTokenRequest creates a token response from any TokenRequest implementation.
func (p *Plugin) createTokenResponseFromTokenRequest(ctx context.Context, request storm.TokenRequest, client storm.Client, opts tokenResponseOpts) (*protocol.AccessTokenResponse, string, error) {
	// Apply pairwise subject transformation if applicable
	request = p.applyPairwise(request, client)

	accessToken, tokenID, refreshToken, validity, err := p.createAccessToken(ctx, request, client, opts.IssueRefresh, opts.CurrentRefreshToken)
	if err != nil {
		return nil, "", err
	}

	// FAPI 2.0: reject requests without sender-constrained proof when required.
	// Must check before resolveCNF so we fail fast without issuing tokens.
	if p.requireDPoP && shared.DPoPFromContext(ctx) == nil {
		return nil, "", protocol.ErrInvalidRequest().WithDescription("DPoP proof required (FAPI 2.0 sender-constrained tokens)")
	}
	if p.requireMtls && shared.ClientCertFromContext(ctx) == nil {
		return nil, "", protocol.ErrInvalidRequest().WithDescription("mTLS client certificate required (FAPI 2.0 sender-constrained tokens)")
	}

	// Resolve cnf claim from mTLS certificate and/or DPoP proof
	cnf := p.resolveCNF(ctx)

	// Store cnf in token metadata if storage supports it
	if cnf != nil {
		if cnfStore, ok := p.tokenStore.(storm.TokenCNFStore); ok {
			_ = cnfStore.SetTokenCNF(ctx, tokenID, cnf)
		}
	}

	idToken, err := p.createIDToken(ctx, request, client, accessToken, opts.Code)
	if err != nil {
		return nil, "", err
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

	return resp, tokenID, nil
}

// resolveCNF builds the cnf (confirmation) claim from mTLS and DPoP context.
// mTLS: cnf.x5t#S256 (RFC 8705 §3.1)

// writeTokenResponse writes a successful token response with optional DPoP-Nonce header.
// RFC 9449 §8: the server MAY include a DPoP-Nonce header in 200 responses.
func (p *Plugin) writeTokenResponse(w http.ResponseWriter, r *http.Request, resp any) {
	if p.dpopNonceSender != nil && shared.DPoPFromContext(r.Context()) != nil {
		p.dpopNonceSender.WriteNonceHeader(w)
	}
	shared.JSONResponse(w, resp, http.StatusOK)
}

// DPoP: cnf.jkt (RFC 9449 §7.1)
// If both are present, both keys are included.
func (p *Plugin) resolveCNF(ctx context.Context) map[string]any {
	var cnf map[string]any

	if cert := shared.ClientCertFromContext(ctx); cert != nil {
		if cnf == nil {
			cnf = make(map[string]any)
		}
		cnf["x5t#S256"] = shared.CertThumbprint(cert)
	}

	if proof := shared.DPoPFromContext(ctx); proof != nil {
		if cnf == nil {
			cnf = make(map[string]any)
		}
		cnf["jkt"] = proof.JWKThumbprint()
	}

	return cnf
}

// createIDToken creates and signs an ID token.
func (p *Plugin) createIDToken(ctx context.Context, request storm.TokenRequest, client storm.Client, accessToken string, code string) (string, error) {
	signingKey, err := p.keyStore.SigningKey(ctx)
	if err != nil {
		return "", err
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
func (p *Plugin) createAccessToken(ctx context.Context, request storm.TokenRequest, client storm.Client, issueRefresh bool, currentRefreshToken string) (encryptedToken string, tokenID string, refreshToken string, validity time.Duration, err error) {
	// Refresh token 颁发条件：
	//   1. 调用方要求颁发（issueRefresh=true）
	//   2. client 声明了 refresh_token grant type
	// 对于 authorization_code grant：只有 response_type 含 code 时 issueRefresh 才为 true
	// 对于 refresh_token grant：始终为 true（刷新后必须返回新 refresh_token）
	needsRefresh := issueRefresh && validateGrantType(client, protocol.GrantTypeRefreshToken)

	var expiration time.Time
	if needsRefresh {
		tokenID, refreshToken, expiration, err = p.tokenStore.CreateAccessAndRefreshTokens(ctx, request, currentRefreshToken)
	} else {
		tokenID, expiration, err = p.tokenStore.CreateAccessToken(ctx, request)
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
	accessToken, _, _, validity, err := p.createAccessToken(ctx, tokenRequest, client, false, "")
	if err != nil {
		return nil, err
	}

	return &protocol.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   protocol.BearerToken,
		ExpiresIn:   uint64(validity.Seconds()),
		Scope:       tokenRequest.GetScopes(),
	}, nil
}
