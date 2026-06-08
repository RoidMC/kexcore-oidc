//go:build create_regression_data

package regression

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

func TestGenerateRegressionData(t *testing.T) {
	dataDir := regressionDataDir()
	require.NoError(t, os.MkdirAll(dataDir, 0755))

	tokenClaimsData := protocol.TokenClaims{
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

	userInfo := &protocol.UserInfo{
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
		Claims: map[string]any{"foo": "bar"},
	}

	testData := map[string]any{
		RegressionAccessTokenClaims: &protocol.AccessTokenClaims{
			TokenClaims: tokenClaimsData,
			Scopes:      []string{"email", "phone"},
			Claims:      map[string]any{"foo": "bar"},
		},
		RegressionIDTokenClaims: &protocol.IDTokenClaims{
			TokenClaims:     tokenClaimsData,
			NotBefore:       12000,
			AccessTokenHash: "acthashhash",
			CodeHash:        "hashhash",
			SessionID:       "666",
			UserInfoProfile: userInfo.UserInfoProfile,
			UserInfoEmail:   userInfo.UserInfoEmail,
			UserInfoPhone:   userInfo.UserInfoPhone,
			Address:         userInfo.Address,
			Claims:          map[string]any{"foo": "bar"},
		},
		RegressionUserInfo: userInfo,
		RegressionJWTProfileAssertionClaims: &protocol.JWTProfileAssertionClaims{
			PrivateKeyID: "8888",
			PrivateKey:   []byte("qwerty"),
			Issuer:       "kexcore",
			Subject:      "kexcore@example.com",
			Audience:     protocol.Audience{"foo", "bar"},
			Expiration:   12345,
			IssuedAt:     12000,
			Claims:       map[string]any{"foo": "bar"},
		},
	}

	for filename, obj := range testData {
		t.Run(filename, func(t *testing.T) {
			data, err := json.MarshalIndent(obj, "", "\t")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dataDir, filename), data, 0644))
			t.Logf("generated %s", filename)
		})
	}
}
