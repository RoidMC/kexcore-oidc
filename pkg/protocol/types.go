package protocol

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/text/language"
)

// ---------------------------------------------------------------------------
// OIDC Core §5.2 — UserInfo / Language Tags
// ---------------------------------------------------------------------------

type Locales []language.Tag

func ParseLocales(tags []string) Locales {
	out := make(Locales, 0, len(tags))
	for _, s := range tags {
		tag, err := language.Parse(s)
		if err == nil && !tag.IsRoot() {
			out = append(out, tag)
		}
	}
	return out
}

func (l Locales) String() string {
	tags := make([]string, len(l))
	for i, tag := range l {
		tags[i] = tag.String()
	}
	return strings.Join(tags, " ")
}

func (l *Locales) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	if s == "" {
		*l = nil
		return nil
	}
	*l = ParseLocales(strings.Split(s, " "))
	return nil
}

func (l Locales) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

func (l *Locales) UnmarshalJSON(data []byte) error {
	var dst any
	if err := json.Unmarshal(data, &dst); err != nil {
		return err
	}
	switch v := dst.(type) {
	case nil:
		*l = nil
	case string:
		*l = ParseLocales(strings.Split(v, " "))
	case []any:
		strs := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return fmt.Errorf("protocol.Locales: unsupported array element type: %T", item)
			}
			strs = append(strs, s)
		}
		*l = ParseLocales(strs)
	default:
		return fmt.Errorf("protocol.Locales: unsupported type: %T", v)
	}
	return nil
}

// ---------------------------------------------------------------------------
// OIDC Core §5.1 — Gender / Locale / Bool
// ---------------------------------------------------------------------------

type Gender string

type Locale struct {
	tag language.Tag
}

func NewLocale(tag language.Tag) *Locale {
	return &Locale{tag: tag}
}

func (l *Locale) Tag() language.Tag {
	if l == nil {
		return language.Und
	}
	return l.tag
}

func (l *Locale) String() string {
	return l.Tag().String()
}

func (l *Locale) MarshalJSON() ([]byte, error) {
	tag := l.Tag()
	if tag.IsRoot() {
		return []byte("null"), nil
	}
	return json.Marshal(tag)
}

func (l *Locale) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "\"\"" {
		return nil
	}
	err := json.Unmarshal(data, &l.tag)
	if err == nil {
		return nil
	}
	var target language.ValueError
	if errors.As(err, &target) {
		l.tag = language.Tag{}
		return nil
	}
	return err
}

// Bool handles both standard JSON booleans and string representations ("true"/"false").
// This is necessary because some OIDC providers (notably AWS Cognito) incorrectly return
// boolean fields like email_verified and phone_number_verified as strings ("true"/"false")
// instead of proper JSON booleans, violating the OIDC specification.
//
// Ref:
// - https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
// - https://docs.aws.amazon.com/cognito/latest/developerguide/userinfo-endpoint.html
type Bool bool

// UnmarshalJSON handles both standard JSON boolean values and string representations.
// This is necessary because some OIDC providers (notably AWS Cognito) incorrectly return
// boolean fields like email_verified and phone_number_verified as strings ("true"/"false")
// instead of proper JSON booleans, violating the OIDC specification.
//
// The method first attempts standard boolean unmarshaling, and falls back to string
// parsing if that fails, making it compatible with both compliant and non-compliant providers.
//
// Ref:
// - https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
// - https://docs.aws.amazon.com/cognito/latest/developerguide/userinfo-endpoint.html
func (b *Bool) UnmarshalJSON(data []byte) error {
	s := string(data)
	switch s {
	case "true", `"true"`:
		*b = true
	case "false", `"false"`:
		*b = false
	default:
		return fmt.Errorf("cannot unmarshal %s into Bool", s)
	}
	return nil
}

// ---------------------------------------------------------------------------
// OIDC Core §2 — Authentication Methods References (AMR)
// ---------------------------------------------------------------------------

type AuthenticationMethodsReferences []string

func (a *AuthenticationMethodsReferences) UnmarshalJSON(data []byte) error {
	var dst any
	if err := json.Unmarshal(data, &dst); err != nil {
		return fmt.Errorf("protocol.AMR: %w", err)
	}

	switch v := dst.(type) {
	case nil:
		*a = nil
	case string:
		*a = AuthenticationMethodsReferences{v}
	case []any:
		refs := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return fmt.Errorf("protocol.AMR: unsupported array element type: %T", item)
			}
			refs = append(refs, s)
		}
		*a = AuthenticationMethodsReferences(refs)
	default:
		return fmt.Errorf("protocol.AMR: unsupported type: %T", v)
	}
	return nil
}

// ---------------------------------------------------------------------------
// OIDC Core §2 — Max Age
// ---------------------------------------------------------------------------

type MaxAge *uint

func NewMaxAge(i uint) MaxAge {
	return &i
}

// ---------------------------------------------------------------------------
// OIDC Core §3.1.2.1 — Authorization Request Parameters
// ---------------------------------------------------------------------------

type ResponseType string

type ResponseMode string

type Display string

const (
	DisplayPage  Display = "page"
	DisplayPopup Display = "popup"
	DisplayTouch Display = "touch"
	DisplayWAP   Display = "wap"
)

func (d *Display) UnmarshalText(text []byte) error {
	switch Display(text) {
	case DisplayPage, DisplayPopup, DisplayTouch, DisplayWAP:
		*d = Display(text)
	}
	return nil
}

// ---------------------------------------------------------------------------
// RFC 6749 §1.4 — Space-Delimited Parameter Encoding
// ---------------------------------------------------------------------------

type SpaceDelimitedArray []string

func (s SpaceDelimitedArray) String() string {
	return strings.Join(s, " ")
}

func (s *SpaceDelimitedArray) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), " ")
	return nil
}

func (s SpaceDelimitedArray) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s SpaceDelimitedArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *SpaceDelimitedArray) UnmarshalJSON(data []byte) error {
	// Try string first (space-delimited, e.g. "openid email profile")
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = strings.Split(str, " ")
		return nil
	}
	// Try JSON array (e.g. ["openid", "email"])
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*s = arr
		return nil
	}
	return fmt.Errorf("cannot unmarshal %s into SpaceDelimitedArray", string(data))
}

func (s *SpaceDelimitedArray) Scan(src any) error {
	if src == nil {
		*s = nil
		return nil
	}
	switch v := src.(type) {
	case string:
		if len(v) == 0 {
			*s = SpaceDelimitedArray{}
			return nil
		}
		*s = strings.Split(v, " ")
	case []byte:
		if len(v) == 0 {
			*s = SpaceDelimitedArray{}
			return nil
		}
		*s = strings.Split(string(v), " ")
	default:
		return fmt.Errorf("cannot convert %T to SpaceDelimitedArray", src)
	}
	return nil
}

func (s SpaceDelimitedArray) Value() (driver.Value, error) {
	return strings.Join(s, " "), nil
}

// ---------------------------------------------------------------------------
// OIDC Core §9 — Client Authentication Methods
// ---------------------------------------------------------------------------

type AuthMethod string

const (
	AuthMethodBasic         AuthMethod = "client_secret_basic"
	AuthMethodPost          AuthMethod = "client_secret_post"
	AuthMethodNone          AuthMethod = "none"
	AuthMethodPrivateKeyJWT AuthMethod = "private_key_jwt"
)

var AllAuthMethods = []AuthMethod{
	AuthMethodBasic, AuthMethodPost, AuthMethodNone, AuthMethodPrivateKeyJWT,
}

// ---------------------------------------------------------------------------
// RFC 6749 §4.1 / §4.4 / §4.5 — Grant Types
// ---------------------------------------------------------------------------

type GrantType string

const (
	GrantTypeCode              GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeBearer            GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantTypeTokenExchange     GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantTypeImplicit          GrantType = "implicit"
	GrantTypeDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTypeCIBA              GrantType = "urn:openid:params:grant-type:ciba"
)

var AllGrantTypes = []GrantType{
	GrantTypeCode, GrantTypeRefreshToken, GrantTypeClientCredentials,
	GrantTypeBearer, GrantTypeTokenExchange, GrantTypeImplicit,
	GrantTypeDeviceCode, GrantTypeCIBA,
}

// ---------------------------------------------------------------------------
// RFC 8693 §2.1 — Token Types (Token Exchange)
// ---------------------------------------------------------------------------

type TokenType string

const (
	AccessTokenType  TokenType = "urn:ietf:params:oauth:token-type:access_token"
	RefreshTokenType TokenType = "urn:ietf:params:oauth:token-type:refresh_token"
	IDTokenType      TokenType = "urn:ietf:params:oauth:token-type:id_token"
	JWTTokenType     TokenType = "urn:ietf:params:oauth:token-type:jwt"
)

var AllTokenTypes = []TokenType{
	AccessTokenType, RefreshTokenType, IDTokenType, JWTTokenType,
}

func (t TokenType) IsSupported() bool {
	return slices.Contains(AllTokenTypes, t)
}

// ---------------------------------------------------------------------------
// OIDC Core §2 — Audience Claim (JSON string or array)
// ---------------------------------------------------------------------------

type Audience []string

func (a *Audience) UnmarshalJSON(text []byte) error {
	var i any
	err := json.Unmarshal(text, &i)
	if err != nil {
		return err
	}
	switch aud := i.(type) {
	case []any:
		*a = make([]string, len(aud))
		for i, audience := range aud {
			(*a)[i] = audience.(string)
		}
	case string:
		*a = []string{aud}
	}
	return nil
}

// ---------------------------------------------------------------------------
// OIDC Core §2 — Time Claim (JSON number or RFC3339 string)
// ---------------------------------------------------------------------------

type Time int64

func (ts Time) AsTime() time.Time {
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(int64(ts), 0)
}

func FromTime(tt time.Time) Time {
	if tt.IsZero() {
		return 0
	}
	return Time(tt.Unix())
}

func NowTime() Time {
	return FromTime(time.Now())
}

func (ts *Time) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("protocol.Time: %w", err)
	}
	switch x := v.(type) {
	case float64:
		*ts = Time(x)
	case string:
		tt, err := time.Parse(time.RFC3339, x)
		if err != nil {
			return fmt.Errorf("protocol.Time: %w", err)
		}
		*ts = FromTime(tt)
	case nil:
		*ts = 0
	default:
		return fmt.Errorf("protocol.Time: unable to parse type %T with value %v", x, x)
	}
	return nil
}
