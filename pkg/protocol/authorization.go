package protocol

import (
	"encoding/json"
	"log/slog"
	"strings"
)

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

	// Hybrid Flow response types (OIDC Core §3.3).
	// These return both an authorization code and tokens in the fragment.
	ResponseTypeCodeIDToken      ResponseType = "code id_token"
	ResponseTypeCodeToken        ResponseType = "code token"
	ResponseTypeCodeIDTokenToken ResponseType = "code id_token token"
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

// JARM (JWT Secured Authorization Response Mode) — RFC 9101
//
//	https://datatracker.ietf.org/doc/html/rfc9101
const (
	// ResponseModeQueryJWT returns the authorization response as a JWT in the query string.
	ResponseModeQueryJWT ResponseMode = "query.jwt"

	// ResponseModeFragmentJWT returns the authorization response as a JWT in the fragment.
	ResponseModeFragmentJWT ResponseMode = "fragment.jwt"

	// ResponseModeFormPostJWT returns the authorization response as a JWT via form post.
	ResponseModeFormPostJWT ResponseMode = "form_post.jwt"
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

	// DPoP JWK Thumbprint for authorization code binding (RFC 9449 §7.1).
	// When present, the token endpoint must verify the DPoP proof matches this thumbprint.
	DPoPJKT string `json:"dpop_jkt" schema:"dpop_jkt"`

	// Resource Indicators (RFC 8707 §2).
	// One or more resource server URIs that the client is requesting access to.
	// The authorization server SHOULD populate the "aud" claim of the access token
	// with these values when issuing JWT access tokens.
	Resource Audience `json:"resource" schema:"resource"`

	// Rich Authorization Requests (RFC 9396 §2).
	// Structured authorization details that express fine-grained access requirements.
	AuthorizationDetails AuthorizationDetails `json:"authorization_details" schema:"authorization_details"`
}

// AuthorizationDetails represents a single element in the authorization_details array.
// RFC 9396 §2 — Authorization Details
// https://datatracker.ietf.org/doc/html/rfc9396#section-2
type AuthorizationDetails []AuthorizationDetail

// UnmarshalText implements encoding.TextUnmarshaler so the form decoder
// can parse the JSON-encoded authorization_details field from OAuth requests.
func (ad *AuthorizationDetails) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	if s == "" {
		return nil
	}
	return json.Unmarshal([]byte(s), ad)
}

// AuthorizationDetail represents a single authorization detail element.
// RFC 9396 §2 — Authorization Details Type
// https://datatracker.ietf.org/doc/html/rfc9396#section-2
type AuthorizationDetail struct {
	// REQUIRED. Type of the authorization details (e.g., "payment_initiation").
	Type string `json:"type"`

	// OPTIONAL. Array of strings representing the locations of the resource servers.
	Locations Audience `json:"locations,omitempty"`

	// OPTIONAL. Array of strings representing the actions the client intends to perform.
	Actions []string `json:"actions,omitempty"`

	// OPTIONAL. Array of strings representing the kinds of data being processed.
	DataTypes []string `json:"datatypes,omitempty"`

	// OPTIONAL. Identifier string for a specific resource instance.
	Identifier string `json:"identifier,omitempty"`

	// OPTIONAL. Array of strings representing the privileges conferred on the client.
	Privileges []string `json:"privileges,omitempty"`
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
	Issuer    string   `json:"iss"`
	Audience  Audience `json:"aud"`
	ExpiresAt int64    `json:"exp,omitempty"` // expiration time (seconds since epoch)
	NotBefore int64    `json:"nbf,omitempty"` // not-valid-before time
	IssuedAt  int64    `json:"iat,omitempty"` // issued-at time
	AuthRequest
}

func (r *RequestObject) GetIssuer() string {
	return r.Issuer
}

func (*RequestObject) SetSignatureAlgorithm(algorithm string) {}
