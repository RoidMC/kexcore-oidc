package protocol_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	"golang.org/x/oauth2"
	"golang.org/x/text/language"
)

var userInfoData = &protocol.UserInfo{
	Subject: "kexcore@example.com",
	UserInfoProfile: protocol.UserInfoProfile{
		Name:              "Test User",
		GivenName:         "Test",
		FamilyName:        "User",
		MiddleName:        "Middle",
		Nickname:          "testuser",
		Profile:           "https://github.com/roidmc",
		Picture:           "https://avatars.githubusercontent.com/u/10137?v=4",
		Website:           "https://kexcore.example.com",
		Gender:            "male",
		Birthdate:         "1st of April",
		Zoneinfo:          "Asia/Shanghai",
		Locale:            protocol.NewLocale(language.Dutch),
		UpdatedAt:         1,
		PreferredUsername: "testuser",
	},
	UserInfoEmail: protocol.UserInfoEmail{
		Email:         "user@kexcore.example.com",
		EmailVerified: true,
	},
	UserInfoPhone: protocol.UserInfoPhone{
		PhoneNumber:         "+1234567890",
		PhoneNumberVerified: true,
	},
	Address: &protocol.UserInfoAddress{
		Formatted:     "Sesame street 666\n666-666, Smallvile\nMoon",
		StreetAddress: "Sesame street 666",
		Locality:      "Smallvile",
		Region:        "Outer space",
		PostalCode:    "666-666",
		Country:       "Moon",
	},
	Claims: map[string]any{
		"foo": "bar",
	},
}

var tokenClaimsData = protocol.TokenClaims{
	Issuer:                              "kexcore",
	Subject:                             "kexcore@example.com",
	Audience:                            protocol.Audience{"foo", "bar"},
	Expiration:                          12345,
	IssuedAt:                            12000,
	JWTID:                               "900",
	AuthorizedParty:                     "bob@example.com",
	Nonce:                               "6969",
	AuthTime:                            12000,
	NotBefore:                           12000,
	AuthenticationContextClassReference: "something",
	AuthenticationMethodsReferences:     []string{"some", "methods"},
	ClientID:                            "777",
	SignatureAlg:                        "ES256",
}

func TestTokenClaims(t *testing.T) {
	claims := tokenClaimsData

	assert.Equal(t, claims.Issuer, tokenClaimsData.GetIssuer())
	assert.Equal(t, claims.Subject, tokenClaimsData.GetSubject())
	assert.Equal(t, []string(claims.Audience), tokenClaimsData.GetAudience())
	assert.Equal(t, claims.Expiration.AsTime(), tokenClaimsData.GetExpiration())
	assert.Equal(t, claims.IssuedAt.AsTime(), tokenClaimsData.GetIssuedAt())
	assert.Equal(t, claims.Nonce, tokenClaimsData.GetNonce())
	assert.Equal(t, claims.AuthTime.AsTime(), tokenClaimsData.GetAuthTime())
	assert.Equal(t, claims.AuthorizedParty, tokenClaimsData.GetAuthorizedParty())
	assert.Equal(t, claims.SignatureAlg, tokenClaimsData.GetSignatureAlgorithm())
	assert.Equal(t, claims.AuthenticationContextClassReference, tokenClaimsData.GetAuthenticationContextClassReference())

	claims.SetSignatureAlgorithm("ES384")
	assert.Equal(t, "ES384", claims.SignatureAlg)
}

func TestNewAccessTokenClaims(t *testing.T) {
	want := &protocol.AccessTokenClaims{
		TokenClaims: protocol.TokenClaims{
			Issuer:     "kexcore",
			Subject:    "kexcore@example.com",
			Audience:   protocol.Audience{"foo"},
			Expiration: 12345,
			ClientID:   "foo",
			JWTID:      "900",
		},
	}

	got := protocol.NewAccessTokenClaims(
		want.Issuer, want.Subject, nil,
		want.Expiration.AsTime(), want.JWTID, "foo", time.Second,
	)

	nowMinusSkew := protocol.NowTime() - 1
	assert.InDelta(t, int64(nowMinusSkew), int64(got.IssuedAt), 1)
	assert.InDelta(t, int64(nowMinusSkew), int64(got.NotBefore), 1)

	got.IssuedAt = 0
	got.NotBefore = 0

	assert.Equal(t, want, got)
}

// ============================================================================
// Tokens
// ============================================================================

func TestTokens(t *testing.T) {
	oauthToken := &oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
	}

	claims := protocol.TokenClaims{
		Issuer:  "kexcore",
		Subject: "kexcore@example.com",
	}

	tokens := &protocol.Tokens[*protocol.IDTokenClaims]{
		Token:         oauthToken,
		IDTokenClaims: &protocol.IDTokenClaims{TokenClaims: claims},
		IDToken:       "id-token-xxx",
	}

	assert.Equal(t, "access-token", tokens.AccessToken)
	assert.Equal(t, "refresh-token", tokens.RefreshToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
	assert.Equal(t, "id-token-xxx", tokens.IDToken)
	assert.Equal(t, "kexcore", tokens.IDTokenClaims.Issuer)
	assert.Equal(t, "kexcore@example.com", tokens.IDTokenClaims.Subject)
}

func TestTokens_EmbeddedOAuth2Methods(t *testing.T) {
	oauthToken := &oauth2.Token{
		AccessToken:  "at",
		RefreshToken: "rt",
		TokenType:    "Bearer",
	}

	tokens := &protocol.Tokens[*protocol.IDTokenClaims]{
		Token: oauthToken,
	}

	require.Equal(t, "at", tokens.AccessToken)
	require.Equal(t, "rt", tokens.RefreshToken)
	require.Equal(t, "Bearer", tokens.TokenType)
}

func TestTokens_NilIDTokenClaims(t *testing.T) {
	oauthToken := &oauth2.Token{
		AccessToken: "at",
		TokenType:   "Bearer",
	}

	tokens := &protocol.Tokens[*protocol.IDTokenClaims]{
		Token:   oauthToken,
		IDToken: "",
	}

	assert.NotNil(t, tokens.Token)
	assert.Nil(t, tokens.IDTokenClaims)
	assert.Empty(t, tokens.IDToken)
}

func TestIDTokenClaims_GetAccessTokenHash(t *testing.T) {
	claims := &protocol.IDTokenClaims{
		AccessTokenHash: "acthashhash",
	}
	assert.Equal(t, "acthashhash", claims.GetAccessTokenHash())
}

func TestIDTokenClaims_SetUserInfo(t *testing.T) {
	want := protocol.IDTokenClaims{
		TokenClaims: protocol.TokenClaims{
			Subject: userInfoData.Subject,
		},
		UserInfoProfile: userInfoData.UserInfoProfile,
		UserInfoEmail:   userInfoData.UserInfoEmail,
		UserInfoPhone:   userInfoData.UserInfoPhone,
		Address:         userInfoData.Address,
		Claims: map[string]any{
			"foo": "bar",
		},
	}

	var got protocol.IDTokenClaims
	got.SetUserInfo(userInfoData)

	assert.Equal(t, want, got)
}

func TestNewIDTokenClaims(t *testing.T) {
	want := &protocol.IDTokenClaims{
		TokenClaims: protocol.TokenClaims{
			Issuer:                              "kexcore",
			Subject:                             "kexcore@example.com",
			Audience:                            protocol.Audience{"foo", "bob@example.com"},
			Expiration:                          12345,
			AuthTime:                            12000,
			Nonce:                               "6969",
			AuthenticationContextClassReference: "something",
			AuthenticationMethodsReferences:     []string{"some", "methods"},
			AuthorizedParty:                     "bob@example.com",
			ClientID:                            "bob@example.com",
		},
	}

	got := protocol.NewIDTokenClaims(
		want.Issuer, want.Subject, want.Audience,
		want.Expiration.AsTime(),
		want.AuthTime.AsTime().Add(time.Second),
		want.Nonce, want.AuthenticationContextClassReference,
		want.AuthenticationMethodsReferences, want.AuthorizedParty,
		time.Second,
	)

	nowMinusSkew := protocol.NowTime() - 1
	assert.InDelta(t, int64(nowMinusSkew), int64(got.IssuedAt), 1)

	got.IssuedAt = 0

	assert.Equal(t, want, got)
}

func TestIDTokenClaims_GetUserInfo(t *testing.T) {
	idTokenData := &protocol.IDTokenClaims{
		TokenClaims:     tokenClaimsData,
		NotBefore:       12000,
		AccessTokenHash: "acthashhash",
		CodeHash:        "hashhash",
		SessionID:       "666",
		UserInfoProfile: userInfoData.UserInfoProfile,
		UserInfoEmail:   userInfoData.UserInfoEmail,
		UserInfoPhone:   userInfoData.UserInfoPhone,
		Address:         userInfoData.Address,
		Claims: map[string]any{
			"foo": "bar",
		},
	}

	want := &protocol.UserInfo{
		Subject:         idTokenData.Subject,
		UserInfoProfile: idTokenData.UserInfoProfile,
		UserInfoEmail:   idTokenData.UserInfoEmail,
		UserInfoPhone:   idTokenData.UserInfoPhone,
		Address:         idTokenData.Address,
		Claims:          idTokenData.Claims,
	}
	got := idTokenData.GetUserInfo()
	assert.Equal(t, want, got)
}

func TestIDTokenClaims_UnmarshalJSON_StringAMR(t *testing.T) {
	var got protocol.IDTokenClaims
	err := json.Unmarshal([]byte(`{"iss":"kexcore","sub":"kexcore@example.com","aud":"foo","exp":12345,"iat":12000,"amr":"pwd"}`), &got)
	assert.NoError(t, err)
	assert.Equal(t, protocol.AuthenticationMethodsReferences{"pwd"}, got.AuthenticationMethodsReferences)
}

func TestNewLogoutTokenClaims(t *testing.T) {
	want := &protocol.LogoutTokenClaims{
		Issuer:     "kexcore",
		Subject:    "kexcore@example.com",
		Audience:   protocol.Audience{"foo", "bob@example.com"},
		Expiration: 12345,
		JWTID:      "jwtID",
		Events: map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": struct{}{},
		},
		SessionID: "sessionID",
		Claims:    nil,
	}

	got := protocol.NewLogoutTokenClaims(
		want.Issuer,
		want.Subject,
		want.Audience,
		want.Expiration.AsTime(),
		want.JWTID,
		want.SessionID,
		1*time.Second,
	)

	nowMinusSkew := protocol.NowTime() - 1
	assert.InDelta(t, int64(nowMinusSkew), int64(got.IssuedAt), 1)

	got.IssuedAt = 0

	assert.Equal(t, want, got)
}
