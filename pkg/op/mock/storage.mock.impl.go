package mock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/op"
)

func NewStorage(t *testing.T) op.Storage {
	return NewMockStorage(gomock.NewController(t))
}

func NewMockStorageExpectValidClientID(t *testing.T) op.Storage {
	m := NewStorage(t)
	ExpectValidClientID(m)
	return m
}

func NewMockStorageExpectInvalidClientID(t *testing.T) op.Storage {
	m := NewStorage(t)
	ExpectInvalidClientID(m)
	return m
}

func NewMockStorageAny(t *testing.T) op.Storage {
	m := NewStorage(t)
	mockS := m.(*MockStorage)
	mockS.EXPECT().GetClientByClientID(gomock.Any(), gomock.Any()).AnyTimes().Return(&ConfClient{}, nil)
	mockS.EXPECT().AuthorizeClientIDSecret(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	return m
}

func NewMockStorageSigningKeyInvalid(t *testing.T) op.Storage {
	m := NewStorage(t)
	//ExpectSigningKeyInvalid(m)
	return m
}

func NewMockStorageSigningKey(t *testing.T) op.Storage {
	m := NewStorage(t)
	//ExpectSigningKey(m)
	return m
}

func ExpectInvalidClientID(s op.Storage) {
	mockS := s.(*MockStorage)
	mockS.EXPECT().GetClientByClientID(gomock.Any(), gomock.Any()).Return(nil, errors.New("client not found"))
}

func ExpectValidClientID(s op.Storage) {
	mockS := s.(*MockStorage)
	mockS.EXPECT().GetClientByClientID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, id string) (op.Client, error) {
			var appType op.ApplicationType
			var authMethod protocol.AuthMethod
			var accessTokenType op.AccessTokenType
			var responseTypes []protocol.ResponseType
			switch id {
			case "web_client":
				appType = op.ApplicationTypeWeb
				authMethod = protocol.AuthMethodBasic
				accessTokenType = op.AccessTokenTypeBearer
				responseTypes = []protocol.ResponseType{protocol.ResponseTypeCode}
			case "native_client":
				appType = op.ApplicationTypeNative
				authMethod = protocol.AuthMethodNone
				accessTokenType = op.AccessTokenTypeBearer
				responseTypes = []protocol.ResponseType{protocol.ResponseTypeCode}
			case "useragent_client":
				appType = op.ApplicationTypeUserAgent
				authMethod = protocol.AuthMethodBasic
				accessTokenType = op.AccessTokenTypeJWT
				responseTypes = []protocol.ResponseType{protocol.ResponseTypeIDToken}
			}
			return &ConfClient{id: id, appType: appType, authMethod: authMethod, accessTokenType: accessTokenType, responseTypes: responseTypes}, nil
		})
}

type ConfClient struct {
	id              string
	appType         op.ApplicationType
	authMethod      protocol.AuthMethod
	accessTokenType op.AccessTokenType
	responseTypes   []protocol.ResponseType
	grantTypes      []oidc.GrantType
	devMode         bool
}

func (c *ConfClient) RedirectURIs() []string {
	return []string{
		"https://registered.com/callback",
		"http://registered.com/callback",
		"http://localhost:9999/callback",
		"custom://callback",
	}
}

func (c *ConfClient) PostLogoutRedirectURIs() []string {
	return []string{}
}

func (c *ConfClient) LoginURL(id string) string {
	return "login?id=" + id
}

func (c *ConfClient) ApplicationType() op.ApplicationType {
	return c.appType
}

func (c *ConfClient) AuthMethod() protocol.AuthMethod {
	return c.authMethod
}

func (c *ConfClient) GetID() string {
	return c.id
}

func (c *ConfClient) AccessTokenLifetime() time.Duration {
	return 5 * time.Minute
}

func (c *ConfClient) IDTokenLifetime() time.Duration {
	return 5 * time.Minute
}

func (c *ConfClient) AccessTokenType() op.AccessTokenType {
	return c.accessTokenType
}

func (c *ConfClient) ResponseTypes() []protocol.ResponseType {
	return c.responseTypes
}

func (c *ConfClient) GrantTypes() []oidc.GrantType {
	return c.grantTypes
}

func (c *ConfClient) DevMode() bool {
	return c.devMode
}

func (c *ConfClient) AllowedScopes() []string {
	return nil
}

func (c *ConfClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *ConfClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *ConfClient) IsScopeAllowed(scope string) bool {
	return false
}

func (c *ConfClient) IDTokenUserinfoClaimsAssertion() bool {
	return false
}

func (c *ConfClient) ClockSkew() time.Duration {
	return 0
}
