package protocol

import (
	"encoding/json"
	"os"
	"time"

	"github.com/muhlemmer/gu"
	"golang.org/x/oauth2"

	"github.com/roidmc/kexcore-oidc/v2/pkg/crypto"
)

// Tokens represents an OAuth2 token response that includes OIDC claims.
type Tokens[C IDClaims] struct {
	*oauth2.Token
	IDTokenClaims C
	IDToken       string
}

// BearerToken defines the token_type `Bearer`, which is returned in a successful token response.
const (
	BearerToken  = "Bearer"
	PrefixBearer = BearerToken + " "

	// BackChannelLogoutEventKey is the event key used in the "events" claim of a Logout Token.
	BackChannelLogoutEventKey = "http://schemas.openid.net/event/backchannel-logout"
)

// ActorClaims provides the `act` claims used for impersonation or delegation Token Exchange.
//
// An actor can be nested in case an obtained token is used as actor token to obtain impersonation or delegation.
// This allows creating a chain of actors.
// See [RFC 8693, section 4.1](https://www.rfc-editor.org/rfc/rfc8693#name-act-actor-claim).
type ActorClaims struct {
	Actor   *ActorClaims   `json:"act,omitempty"`
	Issuer  string         `json:"iss,omitempty"`
	Subject string         `json:"sub,omitempty"`
	Claims  map[string]any `json:"-"`
}

type acAlias ActorClaims

func (c *ActorClaims) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims((*acAlias)(c), c.Claims)
}

func (c *ActorClaims) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, (*acAlias)(c), &c.Claims)
}

// AccessTokenResponse represents a successful OAuth 2.0 token response.
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type AccessTokenResponse struct {
	AccessToken  string              `json:"access_token,omitempty" schema:"access_token,omitempty"`
	TokenType    string              `json:"token_type,omitempty" schema:"token_type,omitempty"`
	RefreshToken string              `json:"refresh_token,omitempty" schema:"refresh_token,omitempty"`
	ExpiresIn    uint64              `json:"expires_in,omitempty" schema:"expires_in,omitempty"`
	IDToken      string              `json:"id_token,omitempty" schema:"id_token,omitempty"`
	State        string              `json:"state,omitempty" schema:"state,omitempty"`
	Scope        SpaceDelimitedArray `json:"scope,omitempty" schema:"scope,omitempty"`
}

// TokenExchangeResponse represents a token exchange response per RFC 8693.
// https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1
type TokenExchangeResponse struct {
	AccessToken     string              `json:"access_token"`
	IssuedTokenType TokenType           `json:"issued_token_type"`
	TokenType       string              `json:"token_type"`
	ExpiresIn       uint64              `json:"expires_in,omitempty"`
	Scopes          SpaceDelimitedArray `json:"scope,omitempty"`
	RefreshToken    string              `json:"refresh_token,omitempty"`
	IDToken         string              `json:"id_token,omitempty"`
}

// LogoutTokenClaims implements OpenID Connect Back-Channel Logout 1.0, section 2.4.
// https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
type LogoutTokenClaims struct {
	Issuer     string         `json:"iss,omitempty"`
	Subject    string         `json:"sub,omitempty"`
	Audience   Audience       `json:"aud,omitempty"`
	IssuedAt   Time           `json:"iat,omitempty"`
	Expiration Time           `json:"exp,omitempty"`
	JWTID      string         `json:"jti,omitempty"`
	Events     map[string]any `json:"events,omitempty"`
	SessionID  string         `json:"sid,omitempty"`
	Claims     map[string]any `json:"-"`
}

type ltcAlias LogoutTokenClaims

func (i *LogoutTokenClaims) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims((*ltcAlias)(i), i.Claims)
}

func (i *LogoutTokenClaims) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, (*ltcAlias)(i), &i.Claims)
}

// NewLogoutTokenClaims creates a new LogoutTokenClaims for back-channel logout.
func NewLogoutTokenClaims(issuer, subject string, audience Audience, expiration time.Time, jwtID, sessionID string, skew time.Duration) *LogoutTokenClaims {
	return &LogoutTokenClaims{
		Issuer:     issuer,
		Subject:    subject,
		Audience:   audience,
		IssuedAt:   FromTime(time.Now().Add(-skew)),
		Expiration: FromTime(expiration),
		JWTID:      jwtID,
		Events: map[string]any{
			BackChannelLogoutEventKey: struct{}{},
		},
		SessionID: sessionID,
	}
}

func (c *LogoutTokenClaims) GetIssuer() string {
	return c.Issuer
}

func (c *LogoutTokenClaims) GetSubject() string {
	return c.Subject
}

func (c *LogoutTokenClaims) GetExpiration() time.Time {
	return c.Expiration.AsTime()
}

func (c *LogoutTokenClaims) GetIssuedAt() time.Time {
	return c.IssuedAt.AsTime()
}

func (c *LogoutTokenClaims) GetAudience() []string {
	return c.Audience
}

func (c *LogoutTokenClaims) GetNonce() string {
	return ""
}

func (c *LogoutTokenClaims) GetAuthTime() time.Time {
	return time.Time{}
}

func (c *LogoutTokenClaims) GetAuthorizedParty() string {
	return ""
}

func (c *LogoutTokenClaims) GetAuthenticationContextClassReference() string {
	return ""
}

func (c *LogoutTokenClaims) SetSignatureAlgorithm(alg string) {}

func (c *LogoutTokenClaims) GetSignatureAlgorithm() string {
	return ""
}

// JWTProfileAssertionClaims implements RFC 7523, section 2.1 for JWT Profile assertions.
// https://datatracker.ietf.org/doc/html/rfc7523#section-2.1
type JWTProfileAssertionClaims struct {
	PrivateKeyID string         `json:"-"`
	PrivateKey   []byte         `json:"-"`
	Issuer       string         `json:"iss"`
	Subject      string         `json:"sub"`
	Audience     Audience       `json:"aud"`
	Expiration   Time           `json:"exp"`
	IssuedAt     Time           `json:"iat"`
	Claims       map[string]any `json:"-"`
}

type jpaAlias JWTProfileAssertionClaims

func (j *JWTProfileAssertionClaims) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims((*jpaAlias)(j), j.Claims)
}

func (j *JWTProfileAssertionClaims) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, (*jpaAlias)(j), &j.Claims)
}

// AssertionOption is a functional option for configuring JWTProfileAssertionClaims.
type AssertionOption func(*JWTProfileAssertionClaims)

// NewJWTProfileAssertion creates a new JWTProfileAssertionClaims for JWT Profile authentication.
func NewJWTProfileAssertion(userID, keyID string, audience []string, key []byte, opts ...AssertionOption) *JWTProfileAssertionClaims {
	j := &JWTProfileAssertionClaims{
		PrivateKey:   key,
		PrivateKeyID: keyID,
		Issuer:       userID,
		Subject:      userID,
		IssuedAt:     FromTime(time.Now().UTC()),
		Expiration:   FromTime(time.Now().Add(1 * time.Hour).UTC()),
		Audience:     audience,
		Claims:       make(map[string]any),
	}
	for _, opt := range opts {
		opt(j)
	}
	return j
}

// JWTProfileDelegatedSubject sets the subject of the JWT Profile assertion to a delegated user.
func JWTProfileDelegatedSubject(sub string) func(*JWTProfileAssertionClaims) {
	return func(j *JWTProfileAssertionClaims) {
		j.Subject = sub
	}
}

// JWTProfileCustomClaim adds a custom claim to the JWT Profile assertion.
func JWTProfileCustomClaim(key string, value any) func(*JWTProfileAssertionClaims) {
	return func(j *JWTProfileAssertionClaims) {
		j.Claims[key] = value
	}
}

// NewJWTProfileAssertionFromFileData creates a JWTProfileAssertionClaims from JSON key data.
func NewJWTProfileAssertionFromFileData(data []byte, audience []string, opts ...AssertionOption) (*JWTProfileAssertionClaims, error) {
	keyData := new(struct {
		KeyID  string `json:"keyId"`
		Key    string `json:"key"`
		UserID string `json:"userId"`
	})
	err := json.Unmarshal(data, keyData)
	if err != nil {
		return nil, err
	}
	return NewJWTProfileAssertion(keyData.UserID, keyData.KeyID, audience, []byte(keyData.Key), opts...), nil
}

// NewJWTProfileAssertionStringFromFileData creates a signed JWT Profile assertion string from JSON key data.
func NewJWTProfileAssertionStringFromFileData(data []byte, audience []string, opts ...AssertionOption) (string, error) {
	keyData := new(struct {
		KeyID  string `json:"keyId"`
		Key    string `json:"key"`
		UserID string `json:"userId"`
	})
	err := json.Unmarshal(data, keyData)
	if err != nil {
		return "", err
	}
	return GenerateJWTProfileToken(NewJWTProfileAssertion(keyData.UserID, keyData.KeyID, audience, []byte(keyData.Key), opts...))
}

// GenerateJWTProfileToken signs and returns a JWT from the given assertion claims.
func GenerateJWTProfileToken(assertion *JWTProfileAssertionClaims) (string, error) {
	privateKey, algorithm, err := crypto.BytesToPrivateKey(assertion.PrivateKey)
	if err != nil {
		return "", err
	}
	signer, err := crypto.NewSigner(algorithm, privateKey, assertion.PrivateKeyID)
	if err != nil {
		return "", err
	}
	marshalledAssertion, err := json.Marshal(assertion)
	if err != nil {
		return "", err
	}
	return signer.Sign(marshalledAssertion)
}

// NewJWTProfileAssertionFromKeyJSON creates a JWTProfileAssertionClaims by reading key data from a file.
func NewJWTProfileAssertionFromKeyJSON(filename string, audience []string, opts ...AssertionOption) (*JWTProfileAssertionClaims, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return NewJWTProfileAssertionFromFileData(data, audience, opts...)
}

// ClaimHash computes the hash of a claim value using the specified signature algorithm.
func ClaimHash(claim string, sigAlgorithm string) (string, error) {
	hash, err := crypto.GetHashAlgorithm(sigAlgorithm)
	if err != nil {
		return "", err
	}
	return crypto.HashString(hash, claim, true), nil
}

// AppendClientIDToAudience appends the clientID to the audience if not already present.
func AppendClientIDToAudience(clientID string, audience []string) []string {
	for _, aud := range audience {
		if aud == clientID {
			return audience
		}
	}
	return append(audience, clientID)
}

// TokenClaims contains the base Claims used all tokens.
// It implements OpenID Connect Core 1.0, section 2.
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
// And RFC 9068: JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens,
// section 2.2. https://datatracker.ietf.org/doc/html/rfc9068#name-data-structure
//
// TokenClaims implements the Claims interface,
// and can be used to extend larger claim types by embedding.
type TokenClaims struct {
	Issuer                              string                          `json:"iss,omitempty"`
	Subject                             string                          `json:"sub,omitempty"`
	Audience                            Audience                        `json:"aud,omitempty"`
	Expiration                          Time                            `json:"exp,omitempty"`
	IssuedAt                            Time                            `json:"iat,omitempty"`
	AuthTime                            Time                            `json:"auth_time,omitempty"`
	NotBefore                           Time                            `json:"nbf,omitempty"`
	Nonce                               string                          `json:"nonce,omitempty"`
	AuthenticationContextClassReference string                          `json:"acr,omitempty"`
	AuthenticationMethodsReferences     AuthenticationMethodsReferences `json:"amr,omitempty"`
	AuthorizedParty                     string                          `json:"azp,omitempty"`
	ClientID                            string                          `json:"client_id,omitempty"`
	JWTID                               string                          `json:"jti,omitempty"`
	Actor                               *ActorClaims                    `json:"act,omitempty"`

	SignatureAlg string `json:"-"`
}

func (c *TokenClaims) GetIssuer() string {
	return c.Issuer
}

func (c *TokenClaims) GetSubject() string {
	return c.Subject
}

func (c *TokenClaims) GetAudience() []string {
	return c.Audience
}

func (c *TokenClaims) GetExpiration() time.Time {
	return c.Expiration.AsTime()
}

func (c *TokenClaims) GetIssuedAt() time.Time {
	return c.IssuedAt.AsTime()
}

func (c *TokenClaims) GetNonce() string {
	return c.Nonce
}

func (c *TokenClaims) GetAuthTime() time.Time {
	return c.AuthTime.AsTime()
}

func (c *TokenClaims) GetAuthorizedParty() string {
	return c.AuthorizedParty
}

func (c *TokenClaims) GetSignatureAlgorithm() string {
	return c.SignatureAlg
}

func (c *TokenClaims) GetAuthenticationContextClassReference() string {
	return c.AuthenticationContextClassReference
}

func (c *TokenClaims) SetSignatureAlgorithm(algorithm string) {
	c.SignatureAlg = algorithm
}

// AccessTokenClaims extends TokenClaims for OAuth 2.0 Access Tokens per RFC 9068.
// https://datatracker.ietf.org/doc/html/rfc9068#name-data-structure
type AccessTokenClaims struct {
	TokenClaims
	Scopes SpaceDelimitedArray `json:"scope,omitempty"`
	Claims map[string]any      `json:"-"`
}

// NewAccessTokenClaims creates a new AccessTokenClaims with the given parameters.
func NewAccessTokenClaims(issuer, subject string, audience []string, expiration time.Time, jwtid, clientID string, skew time.Duration) *AccessTokenClaims {
	now := time.Now().UTC().Add(-skew)
	if len(audience) == 0 {
		audience = append(audience, clientID)
	}
	return &AccessTokenClaims{
		TokenClaims: TokenClaims{
			Issuer:     issuer,
			Subject:    subject,
			Audience:   audience,
			Expiration: FromTime(expiration),
			IssuedAt:   FromTime(now),
			NotBefore:  FromTime(now),
			ClientID:   clientID,
			JWTID:      jwtid,
		},
	}
}

type atcAlias AccessTokenClaims

func (a *AccessTokenClaims) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims((*atcAlias)(a), a.Claims)
}

func (a *AccessTokenClaims) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, (*atcAlias)(a), &a.Claims)
}

// IDTokenClaims extends TokenClaims by further implementing
// OpenID Connect Core 1.0, sections 3.1.3.6 (Code flow),
// 3.2.2.10 (implicit), 3.3.2.11 (Hybrid) and 5.1 (UserInfo).
// https://openid.net/specs/openid-connect-core-1_0.html#toc
type IDTokenClaims struct {
	TokenClaims
	NotBefore       Time   `json:"nbf,omitempty"`
	AccessTokenHash string `json:"at_hash,omitempty"`
	CodeHash        string `json:"c_hash,omitempty"`
	SessionID       string `json:"sid,omitempty"`
	UserInfoProfile
	UserInfoEmail
	UserInfoPhone
	Address *UserInfoAddress `json:"address,omitempty"`
	Claims  map[string]any   `json:"-"`
}

func (t *IDTokenClaims) GetAccessTokenHash() string {
	return t.AccessTokenHash
}

// SetUserInfo populates the IDTokenClaims from a UserInfo response.
func (t *IDTokenClaims) SetUserInfo(i *UserInfo) {
	t.Subject = i.Subject
	t.UserInfoProfile = i.UserInfoProfile
	t.UserInfoEmail = i.UserInfoEmail
	t.UserInfoPhone = i.UserInfoPhone
	t.Address = i.Address
	if t.Claims == nil {
		t.Claims = make(map[string]any, len(t.Claims))
	}
	gu.MapMerge(i.Claims, t.Claims)
}

// GetUserInfo extracts a UserInfo response from the IDTokenClaims.
func (t *IDTokenClaims) GetUserInfo() *UserInfo {
	return &UserInfo{
		Subject:         t.Subject,
		UserInfoProfile: t.UserInfoProfile,
		UserInfoEmail:   t.UserInfoEmail,
		UserInfoPhone:   t.UserInfoPhone,
		Address:         t.Address,
		Claims:          gu.MapCopy(t.Claims),
	}
}

// NewIDTokenClaims creates a new IDTokenClaims with the given parameters.
func NewIDTokenClaims(issuer, subject string, audience []string, expiration, authTime time.Time, nonce string, acr string, amr []string, clientID string, skew time.Duration) *IDTokenClaims {
	audience = AppendClientIDToAudience(clientID, audience)
	return &IDTokenClaims{
		TokenClaims: TokenClaims{
			Issuer:                              issuer,
			Subject:                             subject,
			Audience:                            audience,
			Expiration:                          FromTime(expiration),
			IssuedAt:                            FromTime(time.Now().Add(-skew)),
			AuthTime:                            FromTime(authTime.Add(-skew)),
			Nonce:                               nonce,
			AuthenticationContextClassReference: acr,
			AuthenticationMethodsReferences:     amr,
			AuthorizedParty:                     clientID,
			ClientID:                            clientID,
		},
	}
}

type itcAlias IDTokenClaims

func (i *IDTokenClaims) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims((*itcAlias)(i), i.Claims)
}

func (i *IDTokenClaims) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, (*itcAlias)(i), &i.Claims)
}
