// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package op_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/example/server/storage"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/op"
	"github.com/roidmc/kexcore-oidc/pkg/op/mock"
)

const testIssuer = "https://localhost:9998/"

func newTestProvider(config *op.Config) op.OpenIDProvider {
	return newTestProviderWithCrypto(config, nil)
}

func newTestProviderWithCrypto(config *op.Config, crypto op.Crypto) op.OpenIDProvider {
	stor := storage.NewStorage(storage.NewUserStore(testIssuer))
	keySet := &op.OpenIDKeySet{stor}
	opts := []op.Option{
		op.WithAllowInsecure(),
		op.WithAccessTokenKeySet(keySet),
		op.WithIDTokenHintKeySet(keySet),
	}
	if crypto != nil {
		opts = append(opts, op.WithCrypto(crypto))
	}
	provider, err := op.NewProvider(config, stor, op.StaticIssuer(testIssuer), opts...)
	if err != nil {
		panic(err)
	}
	return provider
}

func TestDiscover(t *testing.T) {
	type args struct {
		w      http.ResponseWriter
		config *oidc.DiscoveryConfiguration
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"OK",
			args{
				httptest.NewRecorder(),
				&oidc.DiscoveryConfiguration{Issuer: "https://issuer.com"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op.Discover(tt.args.w, tt.args.config)
			rec := tt.args.w.(*httptest.ResponseRecorder)
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t,
				`{"issuer":"https://issuer.com","request_uri_parameter_supported":false}
`,
				rec.Body.String())
		})
	}
}

func TestCreateDiscoveryConfig(t *testing.T) {
	type args struct {
		ctx context.Context
		c   op.Configuration
		s   op.DiscoverStorage
	}
	tests := []struct {
		name string
		args args
		want *oidc.DiscoveryConfiguration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.CreateDiscoveryConfig(tt.args.ctx, tt.args.c, tt.args.s)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_scopes(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"default Scopes",
			args{},
			op.DefaultSupportedScopes,
		},
		{
			"custom scopes",
			args{newTestProvider(&op.Config{SupportedScopes: []string{"test1", "test2"}})},
			[]string{"test1", "test2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.Scopes(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_ResponseTypes(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"code and implicit flow",
			args{},
			[]string{"code", "id_token", "id_token token"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.ResponseTypes(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_GrantTypes(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []oidc.GrantType
	}{
		{
			"code and implicit flow",
			args{
				func() op.Configuration {
					c := mock.NewMockConfiguration(gomock.NewController(t))
					c.EXPECT().GrantTypeRefreshTokenSupported().Return(false)
					c.EXPECT().GrantTypeTokenExchangeSupported().Return(false)
					c.EXPECT().GrantTypeJWTAuthorizationSupported().Return(false)
					c.EXPECT().GrantTypeClientCredentialsSupported().Return(false)
					c.EXPECT().GrantTypeDeviceCodeSupported().Return(false)
					return c
				}(),
			},
			[]oidc.GrantType{
				oidc.GrantTypeCode,
				oidc.GrantTypeImplicit,
			},
		},
		{
			"code, implicit flow, refresh token, token exchange, jwt profile, client_credentials",
			args{
				func() op.Configuration {
					c := mock.NewMockConfiguration(gomock.NewController(t))
					c.EXPECT().GrantTypeRefreshTokenSupported().Return(true)
					c.EXPECT().GrantTypeTokenExchangeSupported().Return(true)
					c.EXPECT().GrantTypeJWTAuthorizationSupported().Return(true)
					c.EXPECT().GrantTypeClientCredentialsSupported().Return(true)
					c.EXPECT().GrantTypeDeviceCodeSupported().Return(false)
					return c
				}(),
			},
			[]oidc.GrantType{
				oidc.GrantTypeCode,
				oidc.GrantTypeImplicit,
				oidc.GrantTypeRefreshToken,
				oidc.GrantTypeClientCredentials,
				oidc.GrantTypeTokenExchange,
				oidc.GrantTypeBearer,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.GrantTypes(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_SubjectTypes(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"none",
			args{},
			[]string{"public"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.SubjectTypes(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_SigAlgorithms(t *testing.T) {
	m := mock.NewMockDiscoverStorage(gomock.NewController(t))
	type args struct {
		s op.DiscoverStorage
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"",
			args{func() op.DiscoverStorage {
				m.EXPECT().SignatureAlgorithms(gomock.Any()).Return([]string{"RS256"}, nil)
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.SigAlgorithms(context.Background(), tt.args.s)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_RequestObjectSigAlgorithms(t *testing.T) {
	m := mock.NewMockConfiguration(gomock.NewController(t))
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"not supported, empty",
			args{func() op.Configuration {
				m.EXPECT().RequestObjectSupported().Return(false)
				return m
			}()},
			nil,
		},
		{
			"supported, empty",
			args{func() op.Configuration {
				m.EXPECT().RequestObjectSupported().Return(true)
				m.EXPECT().RequestObjectSigningAlgorithmsSupported().Return(nil)
				return m
			}()},
			nil,
		},
		{
			"supported, list",
			args{func() op.Configuration {
				m.EXPECT().RequestObjectSupported().Return(true)
				m.EXPECT().RequestObjectSigningAlgorithmsSupported().Return([]string{"RS256"})
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.RequestObjectSigAlgorithms(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_AuthMethodsTokenEndpoint(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []oidc.AuthMethod
	}{
		{
			"none and basic",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(false)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic},
		},
		{
			"none, basic and post",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(true)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic, oidc.AuthMethodPost},
		},
		{
			"none, basic, post and private_key_jwt",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(true)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(true)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic, oidc.AuthMethodPost, oidc.AuthMethodPrivateKeyJWT},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.AuthMethodsTokenEndpoint(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_TokenSigAlgorithms(t *testing.T) {
	m := mock.NewMockConfiguration(gomock.NewController(t))
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"not supported, empty",
			args{func() op.Configuration {
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			nil,
		},
		{
			"supported, empty",
			args{func() op.Configuration {
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().TokenEndpointSigningAlgorithmsSupported().Return(nil)
				return m
			}()},
			nil,
		},
		{
			"supported, list",
			args{func() op.Configuration {
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().TokenEndpointSigningAlgorithmsSupported().Return([]string{"RS256"})
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.TokenSigAlgorithms(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_IntrospectionSigAlgorithms(t *testing.T) {
	m := mock.NewMockConfiguration(gomock.NewController(t))
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"not supported, empty",
			args{func() op.Configuration {
				m.EXPECT().IntrospectionAuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			nil,
		},
		{
			"supported, empty",
			args{func() op.Configuration {
				m.EXPECT().IntrospectionAuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().IntrospectionEndpointSigningAlgorithmsSupported().Return(nil)
				return m
			}()},
			nil,
		},
		{
			"supported, list",
			args{func() op.Configuration {
				m.EXPECT().IntrospectionAuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().IntrospectionEndpointSigningAlgorithmsSupported().Return([]string{"RS256"})
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.IntrospectionSigAlgorithms(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_AuthMethodsIntrospectionEndpoint(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []oidc.AuthMethod
	}{
		{
			"basic only",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodBasic},
		},
		{
			"basic and private_key_jwt",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(true)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodBasic, oidc.AuthMethodPrivateKeyJWT},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.AuthMethodsIntrospectionEndpoint(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_RevocationSigAlgorithms(t *testing.T) {
	m := mock.NewMockConfiguration(gomock.NewController(t))
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"not supported, empty",
			args{func() op.Configuration {
				m.EXPECT().RevocationAuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			nil,
		},
		{
			"supported, empty",
			args{func() op.Configuration {
				m.EXPECT().RevocationAuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().RevocationEndpointSigningAlgorithmsSupported().Return(nil)
				return m
			}()},
			nil,
		},
		{
			"supported, list",
			args{func() op.Configuration {
				m.EXPECT().RevocationAuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().RevocationEndpointSigningAlgorithmsSupported().Return([]string{"RS256"})
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.RevocationSigAlgorithms(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_AuthMethodsRevocationEndpoint(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []oidc.AuthMethod
	}{
		{
			"none and basic",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(false)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic},
		},
		{
			"none, basic and post",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(true)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic, oidc.AuthMethodPost},
		},
		{
			"none, basic, post and private_key_jwt",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(true)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(true)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic, oidc.AuthMethodPost, oidc.AuthMethodPrivateKeyJWT},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.AuthMethodsRevocationEndpoint(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSupportedClaims(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"scopes",
			args{},
			[]string{
				"sub",
				"aud",
				"exp",
				"iat",
				"iss",
				"auth_time",
				"nonce",
				"acr",
				"amr",
				"c_hash",
				"at_hash",
				"act",
				"scopes",
				"client_id",
				"azp",
				"preferred_username",
				"name",
				"family_name",
				"given_name",
				"locale",
				"email",
				"email_verified",
				"phone_number",
				"phone_number_verified",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.SupportedClaims(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_CodeChallengeMethods(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []oidc.CodeChallengeMethod
	}{
		{
			"not supported",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().CodeMethodS256Supported().Return(false)
				return m
			}()},
			[]oidc.CodeChallengeMethod{},
		},
		{
			"S256",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().CodeMethodS256Supported().Return(true)
				return m
			}()},
			[]oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.CodeChallengeMethods(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------- JWE Discovery Tests ----------

func Test_IDTokenEncryptionAlgValues(t *testing.T) {
	t.Run("nil crypto returns nil", func(t *testing.T) {
		m := mock.NewMockConfiguration(gomock.NewController(t))
		got := op.IDTokenEncryptionAlgValues(m)
		assert.Nil(t, got)
	})

	t.Run("provider with AES256GCMCrypto returns dir", func(t *testing.T) {
		var key [32]byte
		c := op.NewAES256GCMCrypto(key, "")
		p := newTestProviderWithCrypto(&op.Config{}, c)
		got := op.IDTokenEncryptionAlgValues(p)
		assert.Equal(t, []string{"dir"}, got)
	})

	t.Run("provider with SM4GCMCrypto returns dir", func(t *testing.T) {
		var key [16]byte
		c := op.NewSM4GCMCrypto(key, "")
		p := newTestProviderWithCrypto(&op.Config{}, c)
		got := op.IDTokenEncryptionAlgValues(p)
		assert.Equal(t, []string{"dir"}, got)
	})
}

func Test_IDTokenEncryptionEncValues(t *testing.T) {
	t.Run("nil crypto returns nil", func(t *testing.T) {
		m := mock.NewMockConfiguration(gomock.NewController(t))
		got := op.IDTokenEncryptionEncValues(m)
		assert.Nil(t, got)
	})

	t.Run("provider with AES256GCMCrypto returns all symmetric encs", func(t *testing.T) {
		var key [32]byte
		c := op.NewAES256GCMCrypto(key, "")
		p := newTestProviderWithCrypto(&op.Config{}, c)
		got := op.IDTokenEncryptionEncValues(p)
		assert.ElementsMatch(t, []string{"SGD_SM4_GCM", "A256GCM", "A128GCM"}, got)
	})

	t.Run("provider with SM4GCMCrypto returns all symmetric encs", func(t *testing.T) {
		var key [16]byte
		c := op.NewSM4GCMCrypto(key, "")
		p := newTestProviderWithCrypto(&op.Config{}, c)
		got := op.IDTokenEncryptionEncValues(p)
		assert.ElementsMatch(t, []string{"SGD_SM4_GCM", "A256GCM", "A128GCM"}, got)
	})
}

func Test_CreateDiscoveryConfig_JWEFields(t *testing.T) {
	var key [32]byte
	c := op.NewAES256GCMCrypto(key, "")
	p := newTestProviderWithCrypto(&op.Config{}, c)

	ctx := context.Background()
	storage := mock.NewMockDiscoverStorage(gomock.NewController(t))
	storage.EXPECT().SignatureAlgorithms(gomock.Any()).Return([]string{"RS256"}, nil)

	cfg := op.CreateDiscoveryConfig(ctx, p, storage)

	assert.Equal(t, []string{"dir"}, cfg.IDTokenEncryptionAlgValuesSupported)
	assert.ElementsMatch(t, []string{"SGD_SM4_GCM", "A256GCM", "A128GCM"}, cfg.IDTokenEncryptionEncValuesSupported)
	assert.Equal(t, []string{"dir"}, cfg.JWEAlgValuesSupported)
	assert.ElementsMatch(t, []string{"SGD_SM4_GCM", "A256GCM", "A128GCM"}, cfg.JWEEncValuesSupported)
}
