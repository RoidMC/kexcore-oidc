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
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// New creates a new Token plugin from a PluginContext.
func New(ctx *storm.PluginContext) *Plugin {
	p := &Plugin{
		tokenStore:  ctx.Storage.(storm.TokenStore),
		clientStore: ctx.Storage.(storm.ClientStore),
		authStore:   ctx.Storage.(storm.AuthStore),
		crypto:      ctx.Crypto,
		keyStore:    ctx.Storage.(storm.KeyStore),
		decoder:     ctx.Decoder,
		logger:      slog.Default(),
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
	return &Plugin{
		tokenStore:  cfg.TokenStore,
		clientStore: cfg.ClientStore,
		authStore:   cfg.AuthStore,
		crypto:      cfg.Crypto,
		keyStore:    cfg.KeyStore,
		decoder:     cfg.Decoder,
		logger:      cfg.Logger,
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
		if _, err := p.authenticatePrivateKeyJWT(r, assertion); err != nil {
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
	default:
		tokenError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("unsupported grant_type: %s", grantType))
	}
}

// --- authorization_code grant (RFC 6749 §4.1.3, OIDC Core §3.1.3.1) ---

func (p *Plugin) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	tokenReq, err := parseAccessTokenRequest(r.Form, p.decoder)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("cannot parse token request").WithParent(err))
		return
	}

	if tokenReq.Code == "" {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("code is missing"))
		return
	}

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

	if err := verifyPKCE(authReq, tokenReq.CodeVerifier); err != nil {
		tokenError(w, r, err)
		return
	}

	resp, tokenID, err := p.createTokenResponseFromTokenRequest(r.Context(), authReq, client, true, tokenReq.Code)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	if detector, ok := p.authStore.(storm.CodeReuseDetector); ok && tokenID != "" {
		detector.TrackTokenForAuthRequest(authReq.GetID(), tokenID)
	}

	_ = p.authStore.DeleteAuthRequest(r.Context(), authReq.GetID())

	shared.JSONResponse(w, resp, http.StatusOK)
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

	resp, _, err := p.createTokenResponseFromTokenRequest(r.Context(), refreshReq, client, true, "")
	if err != nil {
		tokenError(w, r, err)
		return
	}

	shared.JSONResponse(w, resp, http.StatusOK)
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

	shared.JSONResponse(w, resp, http.StatusOK)
}

// --- jwt-bearer grant (RFC 7523 §2.1) ---

func (p *Plugin) handleJWTProfile(w http.ResponseWriter, r *http.Request) {
	tokenError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("jwt-bearer grant not yet implemented"))
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

	accessToken, _, _, validity, err := p.createAccessToken(r.Context(), teReq, client)
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

	shared.JSONResponse(w, resp, http.StatusOK)
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

	if !state.Done {
		tokenError(w, r, protocol.ErrAuthorizationPending())
		return
	}

	req := &deviceTokenRequest{
		subject:  state.Subject,
		clientID: clientID,
		scopes:   state.Scopes,
	}

	resp, _, err := p.createTokenResponseFromTokenRequest(r.Context(), req, client, true, "")
	if err != nil {
		tokenError(w, r, err)
		return
	}

	shared.JSONResponse(w, resp, http.StatusOK)
}

// --- client authentication ---

func (p *Plugin) authenticateClient(r *http.Request, formClientID, formClientSecret string) (storm.Client, error) {
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
	issuer := shared.IssuerFromContext(r.Context())
	request, err := protocol.VerifyJWTAssertion(r.Context(), assertion, issuer, p.keyStore, 0)
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithDescription("invalid client_assertion").WithParent(err)
	}

	clientID := request.Issuer
	if clientID == "" {
		return nil, protocol.ErrInvalidClient().WithDescription("client_assertion missing iss claim")
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithParent(err)
	}

	if client.AuthMethod() != protocol.AuthMethodPrivateKeyJWT {
		return nil, protocol.ErrInvalidClient().WithDescription("client not configured for private_key_jwt")
	}

	return client, nil
}

// --- token creation ---

// createTokenResponseFromTokenRequest creates a token response from any TokenRequest implementation.
func (p *Plugin) createTokenResponseFromTokenRequest(ctx context.Context, request storm.TokenRequest, client storm.Client, issueRefresh bool, code string) (*protocol.AccessTokenResponse, string, error) {
	// Apply pairwise subject transformation if applicable
	request = p.applyPairwise(request, client)

	accessToken, tokenID, refreshToken, validity, err := p.createAccessToken(ctx, request, client)
	if err != nil {
		return nil, "", err
	}

	idToken, err := p.createIDToken(ctx, request, client, accessToken, code)
	if err != nil {
		return nil, "", err
	}

	resp := &protocol.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   protocol.BearerToken,
		ExpiresIn:   uint64(validity.Seconds()),
		Scope:       request.GetScopes(),
		IDToken:     idToken,
	}
	if issueRefresh && refreshToken != "" {
		resp.RefreshToken = refreshToken
	}

	return resp, tokenID, nil
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
func (p *Plugin) createAccessToken(ctx context.Context, request storm.TokenRequest, client storm.Client) (encryptedToken string, tokenID string, refreshToken string, validity time.Duration, err error) {
	// Refresh token 应当在以下条件同时满足时颁发：
	//   1. response_type 包含 "code"（authorization code grant 或 hybrid flow），
	//      因为只有 code flow 才会走到 token 端点换取令牌，才能颁发 refresh_token；
	//      implicit flow 的 token 直接从授权端点返回，不在 token 端点颁发。
	//   2. client 声明了 refresh_token grant type（OIDC Core §11 规定
	//      offline_access scope 必须颁发 refresh_token，但即使没有 offline_access，
	//      OP 也允许自主决定颁发——只要 client 有此 grant type 即可）。
	needsRefresh := false
	if authReq, ok := request.(storm.AuthRequest); ok {
		rt := authReq.GetResponseType()
		hasCode := strings.Contains(string(rt), string(protocol.ResponseTypeCode))
		needsRefresh = hasCode &&
			validateGrantType(client, protocol.GrantTypeRefreshToken)
	}

	var expiration time.Time
	if needsRefresh {
		tokenID, refreshToken, expiration, err = p.tokenStore.CreateAccessAndRefreshTokens(ctx, request, "")
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
	accessToken, _, _, validity, err := p.createAccessToken(ctx, tokenRequest, client)
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
