package authorization

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"

	crypto_pkg "github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// --- Client interface adapters ---

// authRequestClientAdapter adapts storm.Client to shared.AuthRequestClient.
// It also forwards optional interface implementations (RedirectURIClient, etc.)
// from the underlying storm.Client to the shared package interfaces.
type authRequestClientAdapter struct {
	storm.Client
}

// RedirectURIs implements shared.RedirectURIClient if the underlying client supports it.
func (a *authRequestClientAdapter) RedirectURIs() []string {
	if rc, ok := a.Client.(interface{ RedirectURIs() []string }); ok {
		return rc.RedirectURIs()
	}
	return nil
}

// RedirectURIGlobs implements shared.RedirectURIGlobClient if the underlying client supports it.
func (a *authRequestClientAdapter) RedirectURIGlobs() []string {
	if rc, ok := a.Client.(interface{ RedirectURIGlobs() []string }); ok {
		return rc.RedirectURIGlobs()
	}
	return nil
}

// StrictScopeValidation implements shared.ScopeValidationClient if the underlying client supports it.
func (a *authRequestClientAdapter) StrictScopeValidation() bool {
	if rc, ok := a.Client.(interface{ StrictScopeValidation() bool }); ok {
		return rc.StrictScopeValidation()
	}
	return false
}

// ApplicationType implements shared.ApplicationTypeClient if the underlying client supports it.
func (a *authRequestClientAdapter) ApplicationType() int {
	if rc, ok := a.Client.(interface{ ApplicationType() int }); ok {
		return rc.ApplicationType()
	}
	return shared.ApplicationTypeWeb
}

// DevMode implements shared.DevModeClient if the underlying client supports it.
func (a *authRequestClientAdapter) DevMode() bool {
	if rc, ok := a.Client.(interface{ DevMode() bool }); ok {
		return rc.DevMode()
	}
	return false
}

// ResponseTypes implements shared.ResponseTypesProvider if the underlying client supports it.
func (a *authRequestClientAdapter) ResponseTypes() []protocol.ResponseType {
	if rc, ok := a.Client.(interface {
		ResponseTypes() []protocol.ResponseType
	}); ok {
		return rc.ResponseTypes()
	}
	return nil
}

// IsScopeAllowed implements the scopeProvider interface if the underlying client supports it.
func (a *authRequestClientAdapter) IsScopeAllowed(scope string) bool {
	if rc, ok := a.Client.(interface{ IsScopeAllowed(string) bool }); ok {
		return rc.IsScopeAllowed(scope)
	}
	return false
}

// --- parsing ---

func parseAuthorizeRequest(form map[string][]string, decoder *protocol.Decoder) (*protocol.AuthRequest, error) {
	req := new(protocol.AuthRequest)
	if err := decoder.Decode(req, form); err != nil {
		return nil, err
	}
	return req, nil
}

// --- validation (delegated to shared package) ---

// validateAuthRequestParamsExceptRedirectURI validates all params except redirect_uri.
// This is called after redirect_uri has been validated separately, so that
// remaining errors can be safely redirected to the registered URI.
// defaultScopes are applied when the client omits the scope parameter (optional).
func validateAuthRequestParamsExceptRedirectURI(client storm.Client, authReq *protocol.AuthRequest, defaultScopes ...string) error {
	return shared.ValidateAuthRequestParamsExceptRedirectURI(&authRequestClientAdapter{client}, authReq, defaultScopes...)
}

// validateRedirectURI validates the redirect_uri parameter.
func validateRedirectURI(client storm.Client, uri string, responseType protocol.ResponseType) error {
	return shared.ValidateRedirectURI(&authRequestClientAdapter{client}, uri, responseType)
}

// validateScopes validates the scope parameter.
// defaultScopes are applied when the client omits the scope parameter (optional).
func validateScopes(client storm.Client, authReq *protocol.AuthRequest, defaultScopes ...string) error {
	return shared.ValidateScopes(&authRequestClientAdapter{client}, authReq, defaultScopes...)
}

// validateResponseType validates the response_type parameter.
func validateResponseType(client storm.Client, responseType protocol.ResponseType) error {
	return shared.ValidateResponseType(&authRequestClientAdapter{client}, responseType)
}

// validatePKCE checks that code_challenge_method is valid when code_challenge is present.
func validatePKCE(authReq *protocol.AuthRequest) error {
	return shared.ValidatePKCE(authReq)
}

// validateNonce enforces that nonce is present for implicit flows.
func validateNonce(authReq *protocol.AuthRequest) error {
	return shared.ValidateNonce(authReq)
}

// isLocalhost returns true if the hostname is a loopback address.
func isLocalhost(host string) bool {
	return shared.IsLocalhost(host)
}

// validatePrompt validates the prompt parameter and mutates authReq accordingly.
func validatePrompt(authReq *protocol.AuthRequest) error {
	return shared.ValidatePrompt(authReq)
}

// httpLoopbackOrLocalhost parses a URL and returns true if it uses HTTP/HTTPS
// and points to a loopback address.
func httpLoopbackOrLocalhost(rawURL string) (*url.URL, bool) {
	return shared.HTTPLoopbackOrLocalhost(rawURL)
}

// --- code creation ---

func createAuthRequestCode(ctx context.Context, authReq storm.AuthRequest, store storm.AuthStore, enc storm.UniCrypto) (string, error) {
	encrypted, err := enc.Encrypt(ctx, []byte(authReq.GetID()))
	if err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(encrypted)
	if err := store.SaveAuthCode(ctx, authReq.GetID(), code); err != nil {
		return "", err
	}
	return code, nil
}

// --- error handling ---

// writeAuthError writes an authorization error response.
// Per OIDC Core §3.1.2.6, errors should be redirected to redirect_uri
// when possible. Falls back to JSON if no redirect_uri is available.
// The error response uses the same response_mode as the successful response
// per OAuth 2.0 Multiple Response Types §2.1 and OIDC Core §3.1.2.6.
func writeAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state string, responseMode protocol.ResponseMode, err error) {
	if redirectURI == "" {
		shared.WriteError(w, r, err, nil)
		return
	}

	protocolErr := protocol.DefaultToServerError(err, err.Error())
	u, parseErr := url.Parse(redirectURI)
	if parseErr != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	params := url.Values{}
	params.Set("error", string(protocolErr.ErrorType))
	params.Set("error_description", protocolErr.Description)
	if state != "" {
		params.Set("state", state)
	}

	switch responseMode {
	case protocol.ResponseModeFragment:
		// Build fragment URL manually: strip any existing fragment from the
		// base URL and append the new fragment parameters.
		base := redirectURI
		if idx := strings.Index(base, "#"); idx >= 0 {
			base = base[:idx]
		}
		http.Redirect(w, r, base+"#"+params.Encode(), http.StatusFound)
		return
	case protocol.ResponseModeFormPost:
		if formPostErr := writeFormPostError(w, redirectURI, params); formPostErr != nil {
			shared.WriteError(w, r, err, nil)
		}
		return
	default:
		// Default: query (per OIDC Core §3.1.2.6 for Authorization Code Flow)
		q := u.Query()
		for key, vals := range params {
			for _, val := range vals {
				q.Add(key, val)
			}
		}
		u.RawQuery = q.Encode()
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// writeFormPostError writes an error response using form_post response mode.
func writeFormPostError(w http.ResponseWriter, redirectURI string, params url.Values) error {
	values := make(map[string][]string)
	for key, vals := range params {
		values[key] = vals
	}

	tmplParams := &struct {
		RedirectURI string
		Params      map[string][]string
	}{
		RedirectURI: redirectURI,
		Params:      values,
	}

	var buf bytes.Buffer
	if err := formPostTmpl.Execute(&buf, tmplParams); err != nil {
		return err
	}

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
	return nil
}

// --- implicit flow helpers ---

// isImplicitResponseType returns true if the response type is an implicit flow
// (id_token only or id_token token). Does NOT include hybrid flows.
func isImplicitResponseType(rt protocol.ResponseType) bool {
	return rt == protocol.ResponseTypeIDTokenOnly ||
		rt == protocol.ResponseTypeIDToken
}

// isHybridResponseType returns true if the response type is a hybrid flow
// (code id_token, code token, or code id_token token).
func isHybridResponseType(rt protocol.ResponseType) bool {
	return rt == protocol.ResponseTypeCodeIDToken ||
		rt == protocol.ResponseTypeCodeToken ||
		rt == protocol.ResponseTypeCodeIDTokenToken
}

// usesFragmentDefault returns true if the response type defaults to fragment
// response mode per OAuth 2.0 Multiple Response Types §2.1.
// Pure code flow uses query; all others (implicit + hybrid) use fragment.
// When response_type is empty (missing/invalid), default to query per
// RFC 6749 §4.1.2.1 — the error response should use the code flow default.
func usesFragmentDefault(rt protocol.ResponseType) bool {
	if rt == "" {
		return false
	}
	return rt != protocol.ResponseTypeCode
}

// resolveResponseMode returns the effective response mode.
// If the explicit response mode is set, it is returned as-is.
// Otherwise, the default is determined by the response type:
//   - code flow → query
//   - implicit/hybrid flows → fragment
func resolveResponseMode(explicit protocol.ResponseMode, rt protocol.ResponseType) protocol.ResponseMode {
	if explicit != "" {
		return explicit
	}
	if usesFragmentDefault(rt) {
		return protocol.ResponseModeFragment
	}
	return protocol.ResponseModeQuery
}

// --- request object helpers ---

// copyRequestObjectToAuthRequest overwrites present values from the Request Object
// into the auth request and clears the RequestParam.
// Per OIDC Core §6.1, Request Object parameters override the top-level parameters.
func copyRequestObjectToAuthRequest(authReq *protocol.AuthRequest, requestObject *protocol.RequestObject) {
	if len(requestObject.Scopes) > 0 {
		authReq.Scopes = requestObject.Scopes
	}
	if requestObject.RedirectURI != "" {
		authReq.RedirectURI = requestObject.RedirectURI
	}
	if requestObject.State != "" {
		authReq.State = requestObject.State
	}
	if requestObject.ResponseMode != "" {
		authReq.ResponseMode = requestObject.ResponseMode
	}
	if requestObject.Nonce != "" {
		authReq.Nonce = requestObject.Nonce
	}
	if requestObject.Display != "" {
		authReq.Display = requestObject.Display
	}
	if len(requestObject.Prompt) > 0 {
		authReq.Prompt = requestObject.Prompt
	}
	if requestObject.MaxAge != nil {
		authReq.MaxAge = requestObject.MaxAge
	}
	if len(requestObject.UILocales) > 0 {
		authReq.UILocales = requestObject.UILocales
	}
	if requestObject.IDTokenHint != "" {
		authReq.IDTokenHint = requestObject.IDTokenHint
	}
	if requestObject.LoginHint != "" {
		authReq.LoginHint = requestObject.LoginHint
	}
	if len(requestObject.ACRValues) > 0 {
		authReq.ACRValues = requestObject.ACRValues
	}
	if requestObject.CodeChallenge != "" {
		authReq.CodeChallenge = requestObject.CodeChallenge
	}
	if requestObject.CodeChallengeMethod != "" {
		authReq.CodeChallengeMethod = requestObject.CodeChallengeMethod
	}
	authReq.RequestParam = ""
}

// --- algorithm helpers ---

// algorithmToJWA converts a string algorithm name to jwa.SignatureAlgorithm.
func algorithmToJWA(alg string) (jwa.SignatureAlgorithm, error) {
	jwaAlg, ok := jwa.LookupSignatureAlgorithm(alg)
	if !ok {
		return jwaAlg, fmt.Errorf("unsupported signing algorithm %q", alg)
	}
	return jwaAlg, nil
}

// hashTokenForIDToken computes the at_hash or c_hash claim value
// per OIDC Core §2 (ID Token) and §3.2.2.1 (Implicit Flow).
//
// The hash is the base64url encoding of the left half of the hash of the token.
//
// Uses UniCrypto.Hash for unified hash computation. If crypto is nil,
// falls back to local computation using pkg/crypto.
func hashTokenForIDToken(token string, sigAlg string, crypto storm.UniCrypto) string {
	if crypto != nil {
		hashBytes, err := crypto.Hash(context.Background(), sigAlg, []byte(token))
		if err == nil && len(hashBytes) > 0 {
			// Take left half and base64url encode
			halfLen := len(hashBytes) / 2
			return base64.RawURLEncoding.EncodeToString(hashBytes[:halfLen])
		}
		// Fall through to local computation on error
	}

	// Fallback to local computation
	h, err := crypto_pkg.GetHashAlgorithm(sigAlg)
	if err != nil {
		return ""
	}
	return crypto_pkg.HashString(h, token, true)
}
