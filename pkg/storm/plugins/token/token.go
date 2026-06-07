// Package token implements the OIDC Token endpoint plugin.
//
// It handles POST /token (RFC 6749 §3.2 / OIDC Core §3.1.3.1),
// supporting the following grant types:
//   - authorization_code (RFC 6749 §4.1.3, OIDC Core §3.1.3.1)
//   - refresh_token (RFC 6749 §6)
//   - client_credentials (RFC 6749 §4.4)
//   - urn:ietf:params:oauth:grant-type:jwt-bearer (RFC 7523 §2.1)
//
// Additional grant types (device_code, token-exchange) are provided
// by separate plugins.
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
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

const validIDTokenLifetime = 1 * time.Hour

// Plugin implements the OIDC Token endpoint.
type Plugin struct {
	tokenStore  storm.TokenStore
	clientStore storm.ClientStore
	authStore   storm.AuthStore
	crypto      storm.UniCrypto
	keyStore    storm.KeyStore
	decoder     *protocol.Decoder
	logger      *slog.Logger
}

// Config holds the dependencies for the Token plugin.
type Config struct {
	TokenStore  storm.TokenStore
	ClientStore storm.ClientStore
	AuthStore   storm.AuthStore
	Crypto      storm.UniCrypto
	KeyStore    storm.KeyStore
	Decoder     *protocol.Decoder
	Logger      *slog.Logger
}

// New creates a new Token plugin from a PluginContext.
// Storage must implement TokenStore, AuthStore, ClientStore, and KeyStore.
func New(ctx *storm.PluginContext) *Plugin {
	return &Plugin{
		tokenStore:  ctx.Storage.(storm.TokenStore),
		clientStore: ctx.Storage.(storm.ClientStore),
		authStore:   ctx.Storage.(storm.AuthStore),
		crypto:      ctx.Crypto,
		keyStore:    ctx.Storage.(storm.KeyStore),
		decoder:     ctx.Decoder,
		logger:      slog.Default(),
	}
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
//
// OIDC standard endpoint: POST /token (RFC 6749 §3.2, OIDC Core §3.1.3.1)
func (p *Plugin) Register(r chi.Router) {
	r.Post("/token", p.handleToken)
}

// Contribute returns the discovery fields for the token endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.TokenEndpoint = shared.EndpointURL(ctx, protocol.NewEndpoint("/token"))

	// Token endpoint capabilities
	cfg.GrantTypesSupported = append(cfg.GrantTypesSupported,
		"client_credentials", "refresh_token",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	)
	cfg.TokenEndpointAuthMethodsSupported = append(cfg.TokenEndpointAuthMethodsSupported,
		"client_secret_basic", "client_secret_post", "private_key_jwt",
	)
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
		_, err := p.authenticatePrivateKeyJWT(r, assertion)
		if err != nil {
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

	// Retrieve the auth request by code
	authReq, err := p.authStore.AuthRequestByCode(r.Context(), tokenReq.Code)
	if err != nil {
		// RFC 6749 §4.1.2: If an authorization code is used more than once,
		// the authorization server MUST revoke all tokens issued based on
		// that authorization code.
		if detector, ok := p.authStore.(storm.CodeReuseDetector); ok {
			detector.RevokeTokensForUsedCode(tokenReq.Code)
		}
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("invalid code").WithParent(err))
		return
	}

	// Authenticate the client
	client, err := p.authenticateClient(r, tokenReq.ClientID, tokenReq.ClientSecret)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	// Validate client matches the auth request
	if client.GetID() != authReq.GetClientID() {
		tokenError(w, r, protocol.ErrInvalidGrant())
		return
	}

	// Validate grant type is allowed for this client
	if !validateGrantType(client, protocol.GrantTypeCode) {
		tokenError(w, r, protocol.ErrUnauthorizedClient().WithDescription("client missing grant_type authorization_code"))
		return
	}

	// Validate redirect_uri matches
	if tokenReq.RedirectURI != "" && tokenReq.RedirectURI != authReq.GetRedirectURI() {
		tokenError(w, r, protocol.ErrInvalidGrant().WithDescription("redirect_uri does not correspond"))
		return
	}

	// PKCE verification (RFC 7636 §4.6)
	if err := verifyPKCE(authReq, tokenReq.CodeVerifier); err != nil {
		tokenError(w, r, err)
		return
	}

	// Create token response using authReq as TokenRequest
	resp, tokenID, err := p.createTokenResponseFromTokenRequest(r.Context(), authReq, client, true)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	// Track token for code reuse detection (RFC 6749 §4.1.2)
	// Use the internal tokenID (UUID), not the encrypted access token string,
	// because s.tokens map is keyed by UUID.
	if detector, ok := p.authStore.(storm.CodeReuseDetector); ok && tokenID != "" {
		detector.TrackTokenForAuthRequest(authReq.GetID(), tokenID)
	}

	// Clean up the auth request
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

	// Authenticate the client
	client, err := p.authenticateClient(r, tokenReq.ClientID, tokenReq.ClientSecret)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	if !validateGrantType(client, protocol.GrantTypeRefreshToken) {
		tokenError(w, r, protocol.ErrUnauthorizedClient())
		return
	}

	// Get the refresh token request data from storage
	refreshReq, err := p.tokenStore.TokenRequestByRefreshToken(r.Context(), tokenReq.RefreshToken)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidGrant().WithParent(err))
		return
	}

	// Validate client matches
	if client.GetID() != refreshReq.GetClientID() {
		tokenError(w, r, protocol.ErrInvalidGrant())
		return
	}

	// Validate requested scopes are a subset
	if err := validateRefreshScopes(tokenReq.Scopes, refreshReq); err != nil {
		tokenError(w, r, err)
		return
	}

	resp, _, err := p.createTokenResponseFromTokenRequest(r.Context(), refreshReq, client, true)
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

	// Authenticate the client
	client, err := p.authenticateClient(r, tokenReq.ClientID, tokenReq.ClientSecret)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	if !validateGrantType(client, protocol.GrantTypeClientCredentials) {
		tokenError(w, r, protocol.ErrUnauthorizedClient())
		return
	}

	// Get token request from storage
	type clientCredentialsStore interface {
		ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (storm.TokenRequest, error)
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
	// TODO: JWT Profile grant requires JWT assertion verification
	tokenError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("jwt-bearer grant not yet implemented"))
}

// --- token exchange grant (RFC 8693) ---

func (p *Plugin) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	// Parse the token exchange request
	req := new(protocol.TokenExchangeRequest)
	if err := p.decoder.Decode(req, r.Form); err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("cannot parse token exchange request").WithParent(err))
		return
	}

	// Required fields
	if req.SubjectToken == "" {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("subject_token missing"))
		return
	}
	if req.SubjectTokenType == "" {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("subject_token_type missing"))
		return
	}

	// Authenticate the client
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

	// Check grant type is allowed for this client
	if !validateGrantType(client, protocol.GrantTypeTokenExchange) {
		tokenError(w, r, protocol.ErrUnauthorizedClient())
		return
	}

	// Resolve subject_token to get the subject
	subject, subjectTokenID, err := p.resolveExchangeToken(r.Context(), req.SubjectToken, req.SubjectTokenType)
	if err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("subject_token is invalid").WithParent(err))
		return
	}

	// Check if storage supports token exchange
	teStore, ok := p.tokenStore.(storm.TokenExchangeStore)
	if !ok {
		tokenError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("token exchange not supported by storage"))
		return
	}

	// Build the internal request
	teReq := &tokenExchangeRequest{
		subject:               subject,
		subjectTokenIDOrToken: subjectTokenID,
		subjectTokenType:      req.SubjectTokenType,
		clientID:              client.GetID(),
		audience:              req.Audience,
		scopes:                req.Scopes,
		requestedTokenType:    req.RequestedTokenType,
	}

	// Default requested_token_type to access_token per RFC 8693 §2.2.1
	if teReq.requestedTokenType == "" {
		teReq.requestedTokenType = protocol.AccessTokenType
	}

	// Validate via storage
	if err := teStore.ValidateTokenExchangeRequest(r.Context(), teReq); err != nil {
		tokenError(w, r, err)
		return
	}

	// Store for audit (best-effort)
	_ = teStore.CreateTokenExchangeRequest(r.Context(), teReq)

	// Create access token
	accessToken, _, _, validity, err := p.createAccessToken(r.Context(), teReq, client)
	if err != nil {
		tokenError(w, r, protocol.ErrServerError().WithParent(err))
		return
	}

	exp := uint64(validity.Seconds())
	resp := &protocol.TokenExchangeResponse{
		AccessToken:     accessToken,
		IssuedTokenType: teReq.requestedTokenType,
		TokenType:       protocol.BearerToken,
		ExpiresIn:       exp,
		Scopes:          teReq.scopes,
	}

	shared.JSONResponse(w, resp, http.StatusOK)
}

// resolveExchangeToken resolves a subject_token to (subject, tokenIDOrToken).
// For refresh tokens, looks up the stored token request.
// For access tokens, decrypts and parses the opaque token.
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

// --- token exchange grant (RFC 8693) ---

// --- client authentication ---

func (p *Plugin) authenticateClient(r *http.Request, formClientID, formClientSecret string) (storm.Client, error) {
	clientID, clientSecret := formClientID, formClientSecret

	// Basic auth takes precedence
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

	// If client uses client_secret_basic or client_secret_post, verify the secret
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
// Returns the response and the internal tokenID (UUID) for code reuse tracking.
func (p *Plugin) createTokenResponseFromTokenRequest(ctx context.Context, request storm.TokenRequest, client storm.Client, createAccessToken bool) (*protocol.AccessTokenResponse, string, error) {
	var accessToken string
	var tokenID string
	var refreshToken string
	var validity time.Duration
	var err error

	if createAccessToken {
		accessToken, tokenID, refreshToken, validity, err = p.createAccessToken(ctx, request, client)
		if err != nil {
			return nil, "", err
		}
	}

	var idToken string
	if p.keyStore != nil {
		idToken, err = p.createIDToken(ctx, request, client, accessToken, "")
		if err != nil {
			p.logger.Error("failed to create ID token", "error", err)
		}
	}

	exp := uint64(validity.Seconds())
	resp := &protocol.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   protocol.BearerToken,
		ExpiresIn:   exp,
		Scope:       request.GetScopes(),
	}
	if refreshToken != "" {
		resp.RefreshToken = refreshToken
	}
	if idToken != "" {
		resp.IDToken = idToken
	}
	return resp, tokenID, nil
}

// createIDToken creates a signed ID token for the given request.
// Supports both standard JWS signing and GM/T signing (SM2/SM9).
// After signing, encrypts the ID token if the client requests it.
func (p *Plugin) createIDToken(ctx context.Context, request storm.TokenRequest, client storm.Client, accessToken, code string) (string, error) {
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
		claims["at_hash"] = p.hashToken(accessToken, signingKey.Algorithm())
	}
	if code != "" {
		claims["c_hash"] = p.hashToken(code, signingKey.Algorithm())
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
	}
	// Merge extra claims from auth request (e.g. claims.id_token requested values).
	// Standard claims set above take precedence and cannot be overridden.
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

	// Try GM/T signing first (SM2/SM9)
	if gmKey, ok := signingKey.(storm.GMSigningKey); ok {
		signed, err = gmKey.GMSigner().Sign(payload)
		if err != nil {
			return "", err
		}
	} else {
		// Sign using the JWK via crypto.SignJWS
		signed, err = crypto.SignJWS(payload, signingKey.Key())
		if err != nil {
			return "", fmt.Errorf("failed to sign ID token: %w", err)
		}
	}

	if encClient, ok := client.(idTokenEncryptionClient); ok {
		alg, enc := encClient.IDTokenEncryptionAlg(), encClient.IDTokenEncryptionEnc()
		if alg != "" && enc != "" {
			encrypted, err := encryptIDToken(signed, p.crypto, alg, enc)
			if err != nil {
				return "", fmt.Errorf("failed to encrypt ID token: %w", err)
			}
			return encrypted, nil
		}
	}

	return signed, nil
}

type idTokenClaimsExtender interface {
	ExtraIDTokenClaims() map[string]any
}

type idTokenEncryptionClient interface {
	IDTokenEncryptionAlg() string
	IDTokenEncryptionEnc() string
}

type tokenEncryptionKeyProvider interface {
	TokenEncryptionKey() []byte
}

type sm2EncryptionKeyProvider interface {
	SM2TokenEncryptionPublicKey() interface{}
}

type sm9EncryptionKeyProvider interface {
	SM9TokenEncryptionKey() *crypto.SM9MasterPublicKey
}

func encryptIDToken(signedToken string, cr storm.UniCrypto, alg, enc string) (string, error) {
	switch alg {
	case protocol.JWEAlgDir:
		kp, ok := cr.(tokenEncryptionKeyProvider)
		if !ok || kp.TokenEncryptionKey() == nil {
			return "", fmt.Errorf("dir encryption requested but Crypto does not implement TokenEncryptionKeyProvider")
		}
		return protocol.EncryptTokenJWE(signedToken, kp.TokenEncryptionKey(), alg, enc)
	case protocol.JWEAlgSM23:
		pk, ok := cr.(sm2EncryptionKeyProvider)
		if !ok || pk.SM2TokenEncryptionPublicKey() == nil {
			return "", fmt.Errorf("SM2 encryption requested but Crypto does not implement SM2TokenEncryptionPublicKeyProvider")
		}
		return protocol.EncryptTokenJWE(signedToken, pk.SM2TokenEncryptionPublicKey(), alg, enc)
	case protocol.JWEAlgSM93:
		pk, ok := cr.(sm9EncryptionKeyProvider)
		if !ok || pk.SM9TokenEncryptionKey() == nil {
			return "", fmt.Errorf("SM9 encryption requested but Crypto does not implement SM9TokenEncryptionKeyProvider")
		}
		return protocol.EncryptTokenSM9(signedToken, pk.SM9TokenEncryptionKey())
	default:
		return "", fmt.Errorf("unsupported JWE key management algorithm: %s", alg)
	}
}

func (p *Plugin) createAccessToken(ctx context.Context, request storm.TokenRequest, client storm.Client) (encryptedToken string, tokenID string, refreshToken string, validity time.Duration, err error) {
	// Determine if we need a refresh token
	needsRefresh := false
	if authReq, ok := request.(storm.AuthRequest); ok {
		needsRefresh = slices.Contains(authReq.GetScopes(), protocol.ScopeOfflineAccess) &&
			authReq.GetResponseType() == protocol.ResponseTypeCode &&
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

	// Encrypt the opaque bearer token.
	plaintext := []byte(tokenID + ":" + request.GetSubject())
	encrypted, err := p.crypto.Encrypt(ctx, plaintext)
	if err != nil {
		return "", "", "", 0, err
	}

	validity = expiration.Sub(time.Now().UTC())
	encryptedToken = base64.RawURLEncoding.EncodeToString(encrypted)
	return encryptedToken, tokenID, refreshToken, validity, nil
}

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

// --- error handling ---

// tokenError writes a token error response.
// Per RFC 6749 §5.2, token errors use HTTP 400 with JSON body.
func tokenError(w http.ResponseWriter, r *http.Request, err error) {
	shared.WriteError(w, r, err, nil)
}

// --- ID token helpers ---

// getNonce extracts the nonce from a TokenRequest if it implements NonceProvider.
func getNonce(req storm.TokenRequest) string {
	type nonceProvider interface {
		GetNonce() string
	}
	if np, ok := req.(nonceProvider); ok {
		return np.GetNonce()
	}
	return ""
}

// hashToken computes the at_hash claim value for the given access token
// using the hash algorithm appropriate for the signing algorithm.
func (p *Plugin) hashToken(accessToken string, sigAlg string) string {
	h, err := crypto.GetHashAlgorithm(sigAlg)
	if err != nil {
		return ""
	}
	return crypto.HashString(h, accessToken, true)
}
