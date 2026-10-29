package authorization

// Authorization response modes: query / fragment / form_post / JARM
// (RFC 6749, OAuth 2.0 Multiple Response Types, OIDC Core §3.1.2.5,
// RFC 9101 JARM) plus Implicit / Hybrid flow token issuance.

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/shared"
)

// defaultIDTokenLifetime is the default lifetime for ID tokens issued
// in the Implicit Flow. Can be overridden per-client via IDTokenLifetimeProvider.
const defaultIDTokenLifetime = 1 * time.Hour

//go:embed template/form_post.html.tmpl
var formPostHtmlTemplate string

var formPostTmpl = template.Must(template.New("form_post").Parse(formPostHtmlTemplate))

// authResponse creates the successful authentication response.
func (p *Plugin) authResponse(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	if authReq.GetResponseType() == protocol.ResponseTypeNone {
		p.authResponseNone(w, r, authReq)
		return
	}

	if authReq.GetResponseType() == protocol.ResponseTypeCode {
		p.authResponseCode(w, r, authReq)
		return
	}

	if p.enableImplicit && isImplicitResponseType(authReq.GetResponseType()) {
		p.authResponseImplicit(w, r, authReq)
		return
	}

	if p.enableImplicit && isHybridResponseType(authReq.GetResponseType()) {
		p.authResponseHybrid(w, r, authReq)
		return
	}

	writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
		resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType()),
		protocol.ErrServerError().WithDescription("unsupported response_type"))
}

// authResponseNone handles response_type=none (OIDC Core §3.2.2.1).
// No authorization code, ID token, or access token is returned.
func (p *Plugin) authResponseNone(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	redirectURI, err := url.Parse(authReq.GetRedirectURI())
	if err != nil {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			"", protocol.ErrServerError().WithDescription("invalid redirect_uri"))
		return
	}
	if state := authReq.GetState(); state != "" {
		q := redirectURI.Query()
		q.Set("state", state)
		redirectURI.RawQuery = q.Encode()
	}
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

// authResponseCode handles the authorization code response.
func (p *Plugin) authResponseCode(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	createCode := createAuthRequestCode
	if p.createAuthCode != nil {
		createCode = p.createAuthCode
	}
	code, err := createCode(r.Context(), authReq, p.authStore, p.crypto)
	if err != nil {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType()),
			protocol.DefaultToServerError(err, "failed to create auth code"))
		return
	}

	redirectURI := authReq.GetRedirectURI()
	responseMode := resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType())

	// Build response payload.
	resp := &codeResponse{
		Code:   code,
		State:  authReq.GetState(),
		Issuer: shared.IssuerFromContext(r.Context()), // RFC 9207
	}

	// Include session_state if client supports it.
	if ssc, ok := authReq.(SessionStateClient); ok {
		resp.SessionState = ssc.GetSessionState()
	}

	// JARM response modes (RFC 9101)
	slog.Info("authorize: checking JARM",
		slog.String("response_mode", string(responseMode)),
		slog.Bool("is_jarm", isJARMResponseMode(responseMode)),
		slog.Bool("has_signer", p.jarmSigner != nil),
	)
	if isJARMResponseMode(responseMode) && p.jarmSigner != nil {
		// Resolve "jwt" shorthand to concrete JARM mode (RFC 9101 §4.1).
		effectiveRM := responseMode
		if responseMode == protocol.ResponseModeJWT {
			if usesFragmentDefault(authReq.GetResponseType()) {
				effectiveRM = protocol.ResponseModeFragmentJWT
			} else {
				effectiveRM = protocol.ResponseModeQueryJWT
			}
		}
		params := map[string]string{
			"code": resp.Code,
		}
		if resp.State != "" {
			params["state"] = resp.State
		}
		if resp.SessionState != "" {
			params["session_state"] = resp.SessionState
		}
		// RFC 9207: iss parameter (JARM JWT already contains iss via issuer claim,
		// but we include it explicitly for consistency)
		if resp.Issuer != "" {
			params["iss"] = resp.Issuer
		}

		slog.Info("authorize: calling SignAuthResponse",
			slog.String("clientID", authReq.GetClientID()),
			slog.Any("params", params),
		)
		jwt, err := p.jarmSigner.SignAuthResponse(r.Context(), params, authReq.GetClientID(), shared.JARMPreferredAlgFromContext(r.Context()))
		if err != nil {
			slog.Error("authorize: JARM signing failed", slog.Any("error", err))
			writeAuthError(w, r, redirectURI, authReq.GetState(), responseMode,
				protocol.DefaultToServerError(err, "failed to sign JARM response"))
			return
		}

		slog.Info("authorize: JARM signed",
			slog.String("effectiveRM", string(effectiveRM)),
			slog.String("redirectURI", redirectURI),
			slog.String("jwt_prefix", truncateStr(jwt, 80)),
		)

		writeJARMResponse(w, r, redirectURI, jwt, effectiveRM)
		return
	}

	// Form Post response mode (OIDC Core §3.1.2.5 / §3.3.2.5)
	if responseMode == protocol.ResponseModeFormPost {
		if err := writeFormPostResponse(w, redirectURI, resp); err != nil {
			writeAuthError(w, r, redirectURI, authReq.GetState(), responseMode, err)
		}
		return
	}

	// Redirect response (query or fragment).
	u, err := url.Parse(redirectURI)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithParent(err), nil)
		return
	}

	params := url.Values{}
	params.Set("code", resp.Code)
	if resp.State != "" {
		params.Set("state", resp.State)
	}
	if resp.SessionState != "" {
		params.Set("session_state", resp.SessionState)
	}
	// RFC 9207: iss parameter in authorization response
	if resp.Issuer != "" {
		params.Set("iss", resp.Issuer)
	}

	// Determine where to place parameters based on response_mode.
	// Per OIDC Core §3.1.2.5 / OAuth 2.0 Multiple Response Types:
	// - explicit query mode -> query
	// - explicit fragment mode -> fragment
	// - default for code flow -> query
	switch responseMode {
	case protocol.ResponseModeFragment:
		u.Fragment = params.Encode()
	case protocol.ResponseModeQuery:
		queries := u.Query()
		for key, vals := range params {
			for _, val := range vals {
				queries.Add(key, val)
			}
		}
		u.RawQuery = queries.Encode()
	default:
		// Default for code flow: query parameters.
		queries := u.Query()
		for key, vals := range params {
			for _, val := range vals {
				queries.Add(key, val)
			}
		}
		u.RawQuery = queries.Encode()
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// writeFormPostResponse writes an HTML form that auto-submits the response.
func writeFormPostResponse(w http.ResponseWriter, redirectURI string, response *codeResponse) error {
	values := make(map[string][]string)
	if response.Code != "" {
		values["code"] = []string{response.Code}
	}
	if response.State != "" {
		values["state"] = []string{response.State}
	}
	if response.SessionState != "" {
		values["session_state"] = []string{response.SessionState}
	}
	// RFC 9207: iss parameter in authorization response
	if response.Issuer != "" {
		values["iss"] = []string{response.Issuer}
	}

	params := &struct {
		RedirectURI string
		Params      map[string][]string
	}{
		RedirectURI: redirectURI,
		Params:      values,
	}

	var buf bytes.Buffer
	if err := formPostTmpl.Execute(&buf, params); err != nil {
		return protocol.ErrServerError().WithParent(err)
	}

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
	return nil
}

// --- implicit flow ---

// authResponseImplicit handles the Implicit Flow response.
//
// Per OIDC Core 1.0 §3.2.2.5 (Successful Authentication Response):
//   - response_type=id_token: returns only id_token in the fragment
//   - response_type=id_token token: returns access_token, token_type, and id_token in the fragment
//
// All response parameters are added to the redirect URI's fragment component,
// per OAuth 2.0 Multiple Response Types Encoding Practice §2.1.
//
// Important: When access_token is returned, the id_token MUST contain the
// at_hash claim (OIDC Core §3.2.2.1). Therefore, we create the access_token
// FIRST and pass it to createImplicitIDToken so it can compute at_hash.
func (p *Plugin) authResponseImplicit(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	if _, err := url.Parse(authReq.GetRedirectURI()); err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithParent(err), nil)
		return
	}

	fragment := url.Values{}
	fragment.Set("state", authReq.GetState())

	// RFC 9207: iss parameter in authorization response
	if iss := shared.IssuerFromContext(r.Context()); iss != "" {
		fragment.Set("iss", iss)
	}

	// Per OIDC Core §3.2.2.5: access_token is returned when response_type is "id_token token" or "token"
	// We create it first so we can pass it to createImplicitIDToken for at_hash computation.
	var accessToken string
	if authReq.GetResponseType() == protocol.ResponseTypeIDToken || authReq.GetResponseType() == protocol.ResponseTypeToken {
		token, expiresIn, err := p.createImplicitAccessToken(r.Context(), authReq)
		if err == nil && token != "" {
			accessToken = token
			fragment.Set("access_token", accessToken)
			fragment.Set("token_type", protocol.BearerToken)
			if expiresIn > 0 {
				fragment.Set("expires_in", fmt.Sprintf("%d", expiresIn))
			}
		}
	}

	// Per OIDC Core §3.2.2.5: id_token is REQUIRED for id_token and id_token token response types
	// When access_token is present, id_token MUST include at_hash (§3.2.2.1)
	if authReq.GetResponseType() == protocol.ResponseTypeIDTokenOnly ||
		authReq.GetResponseType() == protocol.ResponseTypeIDToken {
		// Resolve client for IDTokenLifetimeProvider extension.
		var client storm.Client
		if c, err := p.clientStore.GetClientByClientID(r.Context(), authReq.GetClientID()); err == nil {
			client = c
		}
		idToken, err := p.createImplicitIDToken(r.Context(), authReq, accessToken, "", client)
		if err == nil && idToken != "" {
			fragment.Set("id_token", idToken)
		}
	}

	// Record client session for back-channel logout tracking.
	p.recordSession(r.Context(), authReq)

	// Build fragment URL manually (Go 1.22+ u.RawFragment may not be
	// reflected in u.String() when u.Fragment is also set by url.Parse).
	redirectURL := authReq.GetRedirectURI()
	if idx := strings.Index(redirectURL, "#"); idx >= 0 {
		redirectURL = redirectURL[:idx]
	}
	redirectURL += "#" + fragment.Encode()

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// createImplicitAccessToken creates an access token for the Implicit Flow.
// Per OIDC Core §3.2.2.5, access_token is returned when response_type includes "token".
func (p *Plugin) createImplicitAccessToken(ctx context.Context, authReq storm.AuthRequest) (string, uint64, error) {
	if p.tokenStore == nil || p.crypto == nil {
		return "", 0, nil
	}

	tokenID, expiration, err := p.tokenStore.CreateAccessToken(ctx, authReq, nil)
	if err != nil {
		return "", 0, err
	}

	plaintext := []byte(tokenID + ":" + authReq.GetSubject())
	encrypted, err := p.crypto.Encrypt(ctx, plaintext)
	if err != nil {
		return "", 0, err
	}

	validity := expiration.Sub(time.Now().UTC())
	expiresIn := uint64(validity.Seconds())
	return base64.RawURLEncoding.EncodeToString(encrypted), expiresIn, nil
}

// createImplicitIDToken creates a signed ID token for the Implicit Flow.
//
// Per OIDC Core 1.0 §3.2.2.5 (Successful Authentication Response):
//   - The ID Token is REQUIRED for all Implicit Flow responses
//   - When access_token is also returned (response_type=id_token token),
//     the ID Token MUST contain the at_hash claim (§3.2.2.1)
//
// The at_hash value is the base64url encoding of the left-most half of the
// hash of the octets of the ASCII representation of the access_token value,
// where the hash algorithm used is the hash algorithm used in the alg Header
// Parameter of the ID Token's JOSE Header (OIDC Core §2).
func (p *Plugin) createImplicitIDToken(ctx context.Context, authReq storm.AuthRequest, accessToken, code string, client storm.Client) (string, error) {
	if p.keyStore == nil {
		return "", nil
	}
	signingKey, err := p.keyStore.SigningKey(ctx)
	if err != nil {
		return "", err
	}

	// Determine the ID token signing algorithm:
	// 1. Client's explicit preference (OIDC Core §2: id_token_signed_response_alg)
	// 2. FAPI 2.0 default: PS256 (§5.4 requires PS256, ES256, or EdDSA)
	// 3. Server default (first signing key, typically RS256)
	if client != nil {
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
	}

	// Determine ID token lifetime: per-client override or default (1 hour).
	lifetime := defaultIDTokenLifetime
	if client != nil {
		if lp, ok := client.(IDTokenLifetimeProvider); ok {
			lifetime = lp.IDTokenLifetime()
		}
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss": shared.IssuerFromContext(ctx),
		"sub": authReq.GetSubject(),
		"aud": authReq.GetClientID(),
		"iat": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
	}
	// OIDC Core §3.2.2.1: nonce is REQUIRED for Implicit Flow
	if nonce := authReq.GetNonce(); nonce != "" {
		claims["nonce"] = nonce
	}
	// OIDC Core §2 / §15.1: auth_time is REQUIRED when max_age is requested
	// or when the client requires it via claims parameter.
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
	// OIDC Core §2 / §3.2.2.1: at_hash is REQUIRED when access_token is returned
	// "Access Token hash value. Its value is the base64url encoding of the left-most
	// half of the hash of the octets of the ASCII representation of the access_token value"
	if accessToken != "" {
		claims["at_hash"] = hashTokenForIDToken(accessToken, signingKey.Algorithm(), p.crypto)
	}
	// OIDC Core §3.3.2.11: c_hash is REQUIRED when code is returned in hybrid flow
	if code != "" {
		claims["c_hash"] = hashTokenForIDToken(code, signingKey.Algorithm(), p.crypto)
	}

	// Merge extra claims from auth request (e.g. acr, amr).
	// Standard claims set above take precedence and cannot be overridden.
	if ext, ok := authReq.(IDTokenClaimsExtender); ok {
		for k, v := range ext.ExtraIDTokenClaims() {
			if _, exists := claims[k]; !exists {
				claims[k] = v
			}
		}
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	alg, err := algorithmToJWA(signingKey.Algorithm())
	if err != nil {
		return "", fmt.Errorf("unsupported signing algorithm %q: %w", signingKey.Algorithm(), err)
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.AlgorithmKey, alg)
	if signingKey.ID() != "" {
		_ = headers.Set(jws.KeyIDKey, signingKey.ID())
	}
	signed, err := jws.Sign(payload, jws.WithKey(alg, signingKey.Key(), jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("JWS signing failed: %w", err)
	}
	return string(signed), nil
}

// --- hybrid flow ---

// authResponseHybrid handles the Hybrid Flow response (OIDC Core §3.3).
//
// Hybrid flow returns both an authorization code and tokens in the fragment:
//   - response_type=code id_token: code + id_token
//   - response_type=code token: code + access_token
//   - response_type=code id_token token: code + access_token + id_token
//
// All parameters are returned in the fragment per OAuth 2.0 Multiple Response Types §2.1.
func (p *Plugin) authResponseHybrid(w http.ResponseWriter, r *http.Request, authReq storm.AuthRequest) {
	if _, err := url.Parse(authReq.GetRedirectURI()); err != nil {
		shared.WriteError(w, r, protocol.ErrServerError().WithParent(err), nil)
		return
	}

	fragment := url.Values{}
	fragment.Set("state", authReq.GetState())

	// RFC 9207: iss parameter in authorization response
	if iss := shared.IssuerFromContext(r.Context()); iss != "" {
		fragment.Set("iss", iss)
	}

	// Create authorization code (always present in hybrid flows).
	createCode := createAuthRequestCode
	if p.createAuthCode != nil {
		createCode = p.createAuthCode
	}
	code, err := createCode(r.Context(), authReq, p.authStore, p.crypto)
	if err != nil {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType()),
			protocol.DefaultToServerError(err, "failed to create auth code"))
		return
	}
	fragment.Set("code", code)

	// Create access_token if response_type includes "token".
	var accessToken string
	rt := authReq.GetResponseType()
	if rt == protocol.ResponseTypeCodeToken || rt == protocol.ResponseTypeCodeIDTokenToken {
		token, expiresIn, err := p.createImplicitAccessToken(r.Context(), authReq)
		if err == nil && token != "" {
			accessToken = token
			fragment.Set("access_token", accessToken)
			fragment.Set("token_type", protocol.BearerToken)
			if expiresIn > 0 {
				fragment.Set("expires_in", fmt.Sprintf("%d", expiresIn))
			}
		}
	}

	// Create id_token if response_type includes "id_token".
	if rt == protocol.ResponseTypeCodeIDToken || rt == protocol.ResponseTypeCodeIDTokenToken {
		var client storm.Client
		if c, err := p.clientStore.GetClientByClientID(r.Context(), authReq.GetClientID()); err == nil {
			client = c
		}
		idToken, err := p.createImplicitIDToken(r.Context(), authReq, accessToken, code, client)
		if err == nil && idToken != "" {
			fragment.Set("id_token", idToken)
		}
	}

	// Record client session for back-channel logout tracking.
	p.recordSession(r.Context(), authReq)

	// Build fragment URL.
	redirectURL := authReq.GetRedirectURI()
	if idx := strings.Index(redirectURL, "#"); idx >= 0 {
		redirectURL = redirectURL[:idx]
	}
	redirectURL += "#" + fragment.Encode()

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
