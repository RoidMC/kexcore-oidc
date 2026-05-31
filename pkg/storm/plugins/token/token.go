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
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
	"github.com/roidmc/kexcore-oidc/pkg/util/codec"
)

const validIDTokenLifetime = 1 * time.Hour

// Plugin implements the OIDC Token endpoint.
type Plugin struct {
	tokenStore  storm.TokenStore
	clientStore storm.ClientStore
	authStore   storm.AuthStore
	crypto      storm.Crypto
	keyStore    storm.KeyStore
	converters  map[reflect.Type]codec.Converter
	logger      *slog.Logger
}

// Config holds the dependencies for the Token plugin.
type Config struct {
	TokenStore  storm.TokenStore
	ClientStore storm.ClientStore
	AuthStore   storm.AuthStore
	Crypto      storm.Crypto
	KeyStore    storm.KeyStore
	Converters  map[reflect.Type]codec.Converter
	Logger      *slog.Logger
}

// New creates a new Token plugin.
func New(cfg Config) *Plugin {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Plugin{
		tokenStore:  cfg.TokenStore,
		clientStore: cfg.ClientStore,
		authStore:   cfg.AuthStore,
		crypto:      cfg.Crypto,
		keyStore:    cfg.KeyStore,
		converters:  cfg.Converters,
		logger:      cfg.Logger,
	}
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
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"token_endpoint": shared.IssuerFromContext(ctx) + "/token",
	}
}

// --- main handler ---

func (p *Plugin) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err))
		return
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
	default:
		tokenError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("unsupported grant_type: %s", grantType))
	}
}

// --- authorization_code grant (RFC 6749 §4.1.3, OIDC Core §3.1.3.1) ---

func (p *Plugin) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	tokenReq, err := parseAccessTokenRequest(r.Form, p.converters)
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

	// TODO: PKCE code_verifier validation

	// Create token response using authReq as TokenRequest
	resp, err := p.createTokenResponseFromTokenRequest(r.Context(), authReq, client, true)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	// Clean up the auth request
	_ = p.authStore.DeleteAuthRequest(r.Context(), authReq.GetID())

	shared.JSONResponse(w, resp, http.StatusOK)
}

// --- refresh_token grant (RFC 6749 §6) ---

func (p *Plugin) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	tokenReq, err := parseRefreshTokenRequest(r.Form, p.converters)
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

	resp, err := p.createTokenResponseFromTokenRequest(r.Context(), refreshReq, client, true)
	if err != nil {
		tokenError(w, r, err)
		return
	}

	shared.JSONResponse(w, resp, http.StatusOK)
}

// --- client_credentials grant (RFC 6749 §4.4) ---

func (p *Plugin) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	tokenReq, err := parseClientCredentialsRequest(r.Form, p.converters)
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

// --- parsing ---

func parseAccessTokenRequest(form map[string][]string, converters map[reflect.Type]codec.Converter) (*protocol.AccessTokenRequest, error) {
	req := new(protocol.AccessTokenRequest)
	if err := codec.Decode(req, form, converters); err != nil {
		return nil, err
	}
	return req, nil
}

func parseRefreshTokenRequest(form map[string][]string, converters map[reflect.Type]codec.Converter) (*protocol.RefreshTokenRequest, error) {
	req := new(protocol.RefreshTokenRequest)
	if err := codec.Decode(req, form, converters); err != nil {
		return nil, err
	}
	return req, nil
}

func parseClientCredentialsRequest(form map[string][]string, converters map[reflect.Type]codec.Converter) (*protocol.ClientCredentialsRequest, error) {
	req := new(protocol.ClientCredentialsRequest)
	if err := codec.Decode(req, form, converters); err != nil {
		return nil, err
	}
	return req, nil
}

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
	request, err := shared.VerifyJWTAssertion(r.Context(), assertion, issuer, storm.AdaptKeyStore(p.keyStore), 0)
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

// --- validation ---

func validateGrantType(client storm.Client, grantType protocol.GrantType) bool {
	type grantTypesProvider interface {
		GrantTypes() []protocol.GrantType
	}
	if gp, ok := client.(grantTypesProvider); ok {
		return slices.Contains(gp.GrantTypes(), grantType)
	}
	// If the client doesn't declare grant types, allow common ones
	return grantType == protocol.GrantTypeCode || grantType == protocol.GrantTypeRefreshToken
}

func validateRefreshScopes(requestedScopes []string, refreshReq storm.RefreshTokenRequest) error {
	if len(requestedScopes) == 0 {
		return nil
	}
	for _, scope := range requestedScopes {
		if !slices.Contains(refreshReq.GetScopes(), scope) {
			return protocol.ErrInvalidScope()
		}
	}
	refreshReq.SetCurrentScopes(requestedScopes)
	return nil
}

// --- token creation ---

// createTokenResponseFromTokenRequest creates a token response from any TokenRequest implementation.
func (p *Plugin) createTokenResponseFromTokenRequest(ctx context.Context, request storm.TokenRequest, client storm.Client, createAccessToken bool) (*protocol.AccessTokenResponse, error) {
	var accessToken string
	var validity time.Duration

	if createAccessToken {
		var err error
		accessToken, validity, err = p.createAccessToken(ctx, request, client)
		if err != nil {
			return nil, err
		}
	}

	// Create ID token for OIDC flows if the client supports it.
	// When the KeyStore provides a GMSigningKey, use GM/T signing (SGD_SM3_SM2/SGD_SM3_SM9).
	var idToken string
	if p.keyStore != nil {
		idToken, _ = p.createIDToken(ctx, request, client, accessToken)
	}

	exp := uint64(validity.Seconds())
	resp := &protocol.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   protocol.BearerToken,
		ExpiresIn:   exp,
		Scope:       request.GetScopes(),
	}
	if idToken != "" {
		resp.IDToken = idToken
	}
	return resp, nil
}

// createIDToken creates a signed ID token for the given request.
// Supports both standard JWS signing and GM/T signing (SM2/SM9).
func (p *Plugin) createIDToken(ctx context.Context, request storm.TokenRequest, client storm.Client, accessToken string) (string, error) {
	signingKey, err := p.keyStore.SigningKey(ctx)
	if err != nil {
		return "", err
	}

	// Build ID token claims
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

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// Try GM/T signing first (SM2/SM9)
	if gmKey, ok := signingKey.(storm.GMSigningKey); ok {
		signer := gmKey.GMSigner()
		return signer.Sign(payload)
	}

	// Try GMCrypto signing
	if gm, ok := p.crypto.(storm.GMCrypto); ok {
		return gm.Sign(ctx, signingKey.ID(), payload)
	}

	// Standard signing via jwx (not yet migrated - placeholder)
	// TODO: Implement standard JWS signing using jwx when Signer is migrated
	return "", nil
}

func (p *Plugin) createAccessToken(ctx context.Context, request storm.TokenRequest, client storm.Client) (string, time.Duration, error) {
	// Determine if we need a refresh token
	needsRefresh := false
	if authReq, ok := request.(storm.AuthRequest); ok {
		needsRefresh = slices.Contains(authReq.GetScopes(), protocol.ScopeOfflineAccess) &&
			authReq.GetResponseType() == protocol.ResponseTypeCode &&
			validateGrantType(client, protocol.GrantTypeRefreshToken)
	}

	var tokenID string
	var expiration time.Time
	var err error

	if needsRefresh {
		tokenID, _, expiration, err = p.tokenStore.CreateAccessAndRefreshTokens(ctx, request, "")
	} else {
		tokenID, expiration, err = p.tokenStore.CreateAccessToken(ctx, request)
	}

	if err != nil {
		return "", 0, err
	}

	// Encrypt the opaque bearer token.
	// If the Crypto implementation supports GM/T (GMCrypto), use SM2+SM4-GCM JWE
	// for enhanced security per GM/T 0125.3. Otherwise, fall back to standard encryption.
	plaintext := []byte(tokenID + ":" + request.GetSubject())

	var encrypted []byte
	if gm, ok := p.crypto.(storm.GMCrypto); ok {
		jwe, jweErr := gm.SM2EncryptJWE(ctx, plaintext)
		if jweErr != nil {
			return "", 0, jweErr
		}
		encrypted = []byte(jwe)
	} else {
		encrypted, err = p.crypto.Encrypt(ctx, plaintext)
		if err != nil {
			return "", 0, err
		}
	}

	validity := expiration.Sub(time.Now().UTC())
	return string(encrypted), validity, nil
}

func (p *Plugin) createClientCredentialsResponse(ctx context.Context, tokenRequest storm.TokenRequest, client storm.Client) (*protocol.AccessTokenResponse, error) {
	accessToken, validity, err := p.createAccessToken(ctx, tokenRequest, client)
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
