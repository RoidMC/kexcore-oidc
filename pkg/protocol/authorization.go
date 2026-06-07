package protocol

import "log/slog"

// OIDC Core 1.0 §5.4 — Scope Claims
//
//	https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
const (
	// ScopeOpenID is REQUIRED for all OpenID Requests.
	ScopeOpenID = "openid"

	// ScopeProfile requests access to the End-User's default profile Claims
	// (name, family_name, given_name, middle_name, nickname, preferred_username,
	// profile, picture, website, gender, birthdate, zoneinfo, locale, updated_at).
	ScopeProfile = "profile"

	// ScopeEmail requests access to the email and email_verified Claims.
	ScopeEmail = "email"

	// ScopeAddress requests access to the address Claim.
	ScopeAddress = "address"

	// ScopePhone requests access to the phone_number and phone_number_verified Claims.
	ScopePhone = "phone"

	// ScopeOfflineAccess requests that an OAuth 2.0 Refresh Token be issued.
	// OIDC Core 1.0 §11 (Offline Access)
	ScopeOfflineAccess = "offline_access"
)

// OAuth 2.0 §3.1.1 — Response Types
// OIDC Core 1.0 §3 — Authentication
//
//	https://openid.net/specs/openid-connect-core-1_0.html#Authentication
const (
	// ResponseTypeCode for the Authorization Code Flow.
	// OAuth 2.0 §4.1.1
	ResponseTypeCode ResponseType = "code"

	// ResponseTypeIDToken for the Implicit Flow returning id and access tokens.
	// OIDC Core 1.0 §3.2.2.4
	ResponseTypeIDToken ResponseType = "id_token token"

	// ResponseTypeIDTokenOnly for the Implicit Flow returning only id token.
	// OIDC Core 1.0 §3.2.2.5
	ResponseTypeIDTokenOnly ResponseType = "id_token"
)

// OAuth 2.0 Multiple Response Type Encoding Practice §2.1
//
//	https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
const (
	// ResponseModeQuery returns parameters in the query string of the redirect_uri.
	ResponseModeQuery ResponseMode = "query"

	// ResponseModeFragment returns parameters in the fragment of the redirect_uri.
	ResponseModeFragment ResponseMode = "fragment"

	// ResponseModeFormPost returns parameters via auto-submitting a form.
	// OAuth 2.0 Form Post Response Mode §2.1
	ResponseModeFormPost ResponseMode = "form_post"
)

// OIDC Core 1.0 §3.1.2.1 — Authentication Request (prompt parameter)
//
//	https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
const (
	// PromptNone disallows the OP from displaying any authentication or consent UI pages.
	// An error (login_required, interaction_required, ...) is returned if the user
	// is not already authenticated or consent is needed.
	PromptNone = "none"

	// PromptLogin directs the OP to prompt the End-User for reauthentication.
	PromptLogin = "login"

	// PromptConsent directs the OP to prompt the End-User for consent.
	PromptConsent = "consent"

	// PromptSelectAccount directs the OP to prompt the End-User to select a user account.
	PromptSelectAccount = "select_account"
)

// OIDC Core 1.0 §5.5 — Claims Request Parameter
//
//	https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
//
// The claims parameter value is a JSON object with two top-level members:
//
//	"id_token" and "userinfo", each being a JSON object mapping claim names
//	to either null or a ClaimRequest object.
type ClaimsRequest struct {
	IDToken  map[string]*ClaimRequest `json:"id_token,omitempty"`
	UserInfo map[string]*ClaimRequest `json:"userinfo,omitempty"`
}

// ClaimRequest represents a single claim request specification.
// OIDC Core 1.0 §5.5 — Individual Claims Request
//
//	https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequest
type ClaimRequest struct {
	Essential bool  `json:"essential,omitempty"`
	Value     any   `json:"value,omitempty"`
	Values    []any `json:"values,omitempty"`
}

// HasEssentialClaim checks if a claim is requested as essential in the given claims map.
func HasEssentialClaim(claims map[string]*ClaimRequest, name string) bool {
	if claims == nil {
		return false
	}
	cr, ok := claims[name]
	return ok && cr.Essential
}

// IsClaimRequested checks if a claim is requested (either essential or voluntary) in the claims map.
func IsClaimRequested(claims map[string]*ClaimRequest, name string) bool {
	if claims == nil {
		return false
	}
	_, ok := claims[name]
	return ok
}

// AuthRequest according to:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AuthRequest struct {
	Scopes       SpaceDelimitedArray `json:"scope" schema:"scope"`
	ResponseType ResponseType        `json:"response_type" schema:"response_type"`
	ClientID     string              `json:"client_id" schema:"client_id"`
	RedirectURI  string              `json:"redirect_uri" schema:"redirect_uri"`

	State string `json:"state" schema:"state"`
	Nonce string `json:"nonce" schema:"nonce"`

	ResponseMode ResponseMode        `json:"response_mode" schema:"response_mode"`
	Display      Display             `json:"display" schema:"display"`
	Prompt       SpaceDelimitedArray `json:"prompt" schema:"prompt"`
	MaxAge       *uint               `json:"max_age" schema:"max_age"`
	UILocales    Locales             `json:"ui_locales" schema:"ui_locales"`
	IDTokenHint  string              `json:"id_token_hint" schema:"id_token_hint"`
	LoginHint    string              `json:"login_hint" schema:"login_hint"`
	ACRValues    SpaceDelimitedArray `json:"acr_values" schema:"acr_values"`

	CodeChallenge       string              `json:"code_challenge" schema:"code_challenge"`
	CodeChallengeMethod CodeChallengeMethod `json:"code_challenge_method" schema:"code_challenge_method"`

	RequestParam string         `schema:"request"`
	RequestURI   string         `schema:"request_uri"`
	Claims       *ClaimsRequest `json:"claims" schema:"claims"`
}

// PushedAuthRequest represents the parameters sent to the Pushed Authorization Request endpoint.
// https://datatracker.ietf.org/doc/html/rfc9126#section-2.1
type PushedAuthRequest struct {
	AuthRequest
}

// PushedAuthResponse is the successful response from the Pushed Authorization Request endpoint.
// https://datatracker.ietf.org/doc/html/rfc9126#section-2.2
type PushedAuthResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func (a *AuthRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("scopes", a.Scopes),
		slog.String("response_type", string(a.ResponseType)),
		slog.String("client_id", a.ClientID),
		slog.String("redirect_uri", a.RedirectURI),
	)
}

func (a *AuthRequest) GetRedirectURI() string {
	return a.RedirectURI
}

func (a *AuthRequest) GetResponseType() ResponseType {
	return a.ResponseType
}

func (a *AuthRequest) GetState() string {
	return a.State
}

func (a *AuthRequest) GetResponseMode() ResponseMode {
	return a.ResponseMode
}

// RequestObject represents an OIDC Request Object (JWS/JWE encoded AuthRequest).
// OIDC Core 1.0 §6.1 — Passing a Request Object by Value
// https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
type RequestObject struct {
	Issuer   string   `json:"iss"`
	Audience Audience `json:"aud"`
	AuthRequest
}

func (r *RequestObject) GetIssuer() string {
	return r.Issuer
}

func (*RequestObject) SetSignatureAlgorithm(algorithm string) {}
