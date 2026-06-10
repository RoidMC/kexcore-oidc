package protocol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	ClientAssertionTypeJWTAssertion = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type TokenRequestType GrantType

type AccessTokenRequest struct {
	GrantType           string `schema:"grant_type,omitempty"`
	Code                string `schema:"code"`
	RedirectURI         string `schema:"redirect_uri"`
	ClientID            string `schema:"client_id"`
	ClientSecret        string `schema:"client_secret,omitempty"`
	CodeVerifier        string `schema:"code_verifier,omitempty"`
	ClientAssertion     string `schema:"client_assertion,omitempty"`
	ClientAssertionType string `schema:"client_assertion_type,omitempty"`
}

func (a *AccessTokenRequest) SetClientID(clientID string) {
	a.ClientID = clientID
}

func (a *AccessTokenRequest) SetClientSecret(clientSecret string) {
	a.ClientSecret = clientSecret
}

type RefreshTokenRequest struct {
	GrantType           string              `schema:"grant_type,omitempty"`
	RefreshToken        string              `schema:"refresh_token"`
	Scopes              SpaceDelimitedArray `schema:"scope"`
	ClientID            string              `schema:"client_id"`
	ClientSecret        string              `schema:"client_secret"`
	ClientAssertion     string              `schema:"client_assertion"`
	ClientAssertionType string              `schema:"client_assertion_type"`
}

func (a *RefreshTokenRequest) SetClientID(clientID string) {
	a.ClientID = clientID
}

func (a *RefreshTokenRequest) SetClientSecret(clientSecret string) {
	a.ClientSecret = clientSecret
}

type JWTTokenRequest struct {
	Issuer    string              `json:"iss"`
	Subject   string              `json:"sub"`
	Scopes    SpaceDelimitedArray `json:"-"`
	Audience  Audience            `json:"aud"`
	IssuedAt  Time                `json:"iat"`
	ExpiresAt Time                `json:"exp"`

	private map[string]any
}

func (j *JWTTokenRequest) MarshalJSON() ([]byte, error) {
	type Alias JWTTokenRequest
	a := (*Alias)(j)

	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	if len(j.private) == 0 {
		return b, nil
	}

	err = json.Unmarshal(b, &j.private)
	if err != nil {
		return nil, fmt.Errorf("jws: invalid map of custom claims %v", j.private)
	}

	return json.Marshal(j.private)
}

func (j *JWTTokenRequest) UnmarshalJSON(data []byte) error {
	type Alias JWTTokenRequest
	a := (*Alias)(j)

	err := json.Unmarshal(data, a)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &j.private)
	if err != nil {
		return err
	}

	return nil
}

func (j *JWTTokenRequest) GetCustomClaim(key string) any {
	return j.private[key]
}

func (j *JWTTokenRequest) GetIssuer() string {
	return j.Issuer
}

func (j *JWTTokenRequest) GetAudience() []string {
	return j.Audience
}

func (j *JWTTokenRequest) GetExpiration() time.Time {
	return j.ExpiresAt.AsTime()
}

func (j *JWTTokenRequest) GetIssuedAt() time.Time {
	return j.IssuedAt.AsTime()
}

func (j *JWTTokenRequest) GetNonce() string {
	return ""
}

func (j *JWTTokenRequest) GetAuthenticationContextClassReference() string {
	return ""
}

func (j *JWTTokenRequest) GetAuthTime() time.Time {
	return time.Time{}
}

func (j *JWTTokenRequest) GetAuthorizedParty() string {
	return ""
}

func (j *JWTTokenRequest) SetSignatureAlgorithm(_ string) {}

func (j *JWTTokenRequest) GetSubject() string {
	return j.Subject
}

func (j *JWTTokenRequest) GetScopes() []string {
	return j.Scopes
}

type TokenExchangeRequest struct {
	GrantType          GrantType           `schema:"grant_type"`
	SubjectToken       string              `schema:"subject_token"`
	SubjectTokenType   TokenType           `schema:"subject_token_type"`
	ActorToken         string              `schema:"actor_token"`
	ActorTokenType     TokenType           `schema:"actor_token_type"`
	Resource           []string            `schema:"resource"`
	Audience           Audience            `schema:"audience"`
	Scopes             SpaceDelimitedArray `schema:"scope"`
	RequestedTokenType TokenType           `schema:"requested_token_type"`
}

type ClientCredentialsRequest struct {
	GrantType           GrantType           `schema:"grant_type,omitempty"`
	Scope               SpaceDelimitedArray `schema:"scope"`
	ClientID            string              `schema:"client_id"`
	ClientSecret        string              `schema:"client_secret"`
	ClientAssertion     string              `schema:"client_assertion,omitempty"`
	ClientAssertionType string              `schema:"client_assertion_type,omitempty"`
}

func (r *ClientCredentialsRequest) Auth(req *http.Request) {
	if r.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(r.ClientID), url.QueryEscape(r.ClientSecret))
	}
}

type JWTProfileGrantRequest struct {
	Assertion string              `schema:"assertion"`
	Scope     SpaceDelimitedArray `schema:"scope"`
	GrantType GrantType           `schema:"grant_type"`
}

func NewJWTProfileGrantRequest(assertion string, scopes ...string) *JWTProfileGrantRequest {
	return &JWTProfileGrantRequest{
		GrantType: GrantTypeBearer,
		Assertion: assertion,
		Scope:     scopes,
	}
}
