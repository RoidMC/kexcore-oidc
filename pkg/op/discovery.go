// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package op

import (
	"context"
	"net/http"

	httphelper "github.com/roidmc/kexcore-oidc/pkg/http"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
)

type DiscoverStorage interface {
	SignatureAlgorithms(context.Context) ([]string, error)
}

var DefaultSupportedScopes = []string{
	oidc.ScopeOpenID,
	oidc.ScopeProfile,
	oidc.ScopeEmail,
	oidc.ScopePhone,
	oidc.ScopeAddress,
	oidc.ScopeOfflineAccess,
}

func discoveryHandler(c Configuration, s DiscoverStorage) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Discover(w, CreateDiscoveryConfig(r.Context(), c, s))
	}
}

func Discover(w http.ResponseWriter, config *oidc.DiscoveryConfiguration) {
	httphelper.MarshalJSON(w, config)
}

func CreateDiscoveryConfig(ctx context.Context, config Configuration, storage DiscoverStorage) *oidc.DiscoveryConfiguration {
	issuer := IssuerFromContext(ctx)
	return &oidc.DiscoveryConfiguration{
		Issuer:                                             issuer,
		AuthorizationEndpoint:                              config.AuthorizationEndpoint().Absolute(issuer),
		TokenEndpoint:                                      config.TokenEndpoint().Absolute(issuer),
		IntrospectionEndpoint:                              config.IntrospectionEndpoint().Absolute(issuer),
		UserinfoEndpoint:                                   config.UserinfoEndpoint().Absolute(issuer),
		RevocationEndpoint:                                 config.RevocationEndpoint().Absolute(issuer),
		EndSessionEndpoint:                                 config.EndSessionEndpoint().Absolute(issuer),
		JwksURI:                                            config.KeysEndpoint().Absolute(issuer),
		DeviceAuthorizationEndpoint:                        config.DeviceAuthorizationEndpoint().Absolute(issuer),
		CheckSessionIframe:                                 config.CheckSessionIframe().Absolute(issuer),
		ScopesSupported:                                    Scopes(config),
		ResponseTypesSupported:                             ResponseTypes(config),
		GrantTypesSupported:                                GrantTypes(config),
		SubjectTypesSupported:                              SubjectTypes(config),
		IDTokenSigningAlgValuesSupported:                   SigAlgorithms(ctx, storage),
		IDTokenEncryptionAlgValuesSupported:                IDTokenEncryptionAlgValues(config),
		IDTokenEncryptionEncValuesSupported:                IDTokenEncryptionEncValues(config),
		RequestObjectSigningAlgValuesSupported:             RequestObjectSigAlgorithms(config),
		TokenEndpointAuthMethodsSupported:                  AuthMethodsTokenEndpoint(config),
		TokenEndpointAuthSigningAlgValuesSupported:         TokenSigAlgorithms(config),
		IntrospectionEndpointAuthSigningAlgValuesSupported: IntrospectionSigAlgorithms(config),
		IntrospectionEndpointAuthMethodsSupported:          AuthMethodsIntrospectionEndpoint(config),
		RevocationEndpointAuthSigningAlgValuesSupported:    RevocationSigAlgorithms(config),
		RevocationEndpointAuthMethodsSupported:             AuthMethodsRevocationEndpoint(config),
		ClaimsSupported:                                    SupportedClaims(config),
		CodeChallengeMethodsSupported:                      CodeChallengeMethods(config),
		UILocalesSupported:                                 config.SupportedUILocales(),
		RequestParameterSupported:                          config.RequestObjectSupported(),
		BackChannelLogoutSupported:                         config.BackChannelLogoutSupported(),
		BackChannelLogoutSessionSupported:                  config.BackChannelLogoutSessionSupported(),
		JWEAlgValuesSupported:                              IDTokenEncryptionAlgValues(config),
		JWEEncValuesSupported:                              IDTokenEncryptionEncValues(config),
	}
}

func createDiscoveryConfigV2(ctx context.Context, config Configuration, storage DiscoverStorage, endpoints *Endpoints) *oidc.DiscoveryConfiguration {
	issuer := IssuerFromContext(ctx)
	return &oidc.DiscoveryConfiguration{
		Issuer:                                             issuer,
		AuthorizationEndpoint:                              endpoints.Authorization.Absolute(issuer),
		TokenEndpoint:                                      endpoints.Token.Absolute(issuer),
		IntrospectionEndpoint:                              endpoints.Introspection.Absolute(issuer),
		UserinfoEndpoint:                                   endpoints.Userinfo.Absolute(issuer),
		RevocationEndpoint:                                 endpoints.Revocation.Absolute(issuer),
		EndSessionEndpoint:                                 endpoints.EndSession.Absolute(issuer),
		JwksURI:                                            endpoints.JwksURI.Absolute(issuer),
		DeviceAuthorizationEndpoint:                        endpoints.DeviceAuthorization.Absolute(issuer),
		ScopesSupported:                                    Scopes(config),
		ResponseTypesSupported:                             ResponseTypes(config),
		GrantTypesSupported:                                GrantTypes(config),
		SubjectTypesSupported:                              SubjectTypes(config),
		IDTokenSigningAlgValuesSupported:                   SigAlgorithms(ctx, storage),
		IDTokenEncryptionAlgValuesSupported:                IDTokenEncryptionAlgValues(config),
		IDTokenEncryptionEncValuesSupported:                IDTokenEncryptionEncValues(config),
		RequestObjectSigningAlgValuesSupported:             RequestObjectSigAlgorithms(config),
		TokenEndpointAuthMethodsSupported:                  AuthMethodsTokenEndpoint(config),
		TokenEndpointAuthSigningAlgValuesSupported:         TokenSigAlgorithms(config),
		IntrospectionEndpointAuthSigningAlgValuesSupported: IntrospectionSigAlgorithms(config),
		IntrospectionEndpointAuthMethodsSupported:          AuthMethodsIntrospectionEndpoint(config),
		RevocationEndpointAuthSigningAlgValuesSupported:    RevocationSigAlgorithms(config),
		RevocationEndpointAuthMethodsSupported:             AuthMethodsRevocationEndpoint(config),
		ClaimsSupported:                                    SupportedClaims(config),
		CodeChallengeMethodsSupported:                      CodeChallengeMethods(config),
		UILocalesSupported:                                 config.SupportedUILocales(),
		RequestParameterSupported:                          config.RequestObjectSupported(),
		BackChannelLogoutSupported:                         config.BackChannelLogoutSupported(),
		BackChannelLogoutSessionSupported:                  config.BackChannelLogoutSessionSupported(),
		JWEAlgValuesSupported:                              IDTokenEncryptionAlgValues(config),
		JWEEncValuesSupported:                              IDTokenEncryptionEncValues(config),
	}
}

func Scopes(c Configuration) []string {
	provider, ok := c.(*Provider)
	if ok && provider.config.SupportedScopes != nil {
		return provider.config.SupportedScopes
	}
	return DefaultSupportedScopes
}

func ResponseTypes(c Configuration) []string {
	return []string{
		string(oidc.ResponseTypeCode),
		string(oidc.ResponseTypeIDTokenOnly),
		string(oidc.ResponseTypeIDToken),
	} // TODO: ok for now, check later if dynamic needed
}

func GrantTypes(c Configuration) []oidc.GrantType {
	grantTypes := []oidc.GrantType{
		oidc.GrantTypeCode,
		oidc.GrantTypeImplicit,
	}
	if c.GrantTypeRefreshTokenSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeRefreshToken)
	}
	if c.GrantTypeClientCredentialsSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeClientCredentials)
	}
	if c.GrantTypeTokenExchangeSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeTokenExchange)
	}
	if c.GrantTypeJWTAuthorizationSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeBearer)
	}
	if c.GrantTypeDeviceCodeSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeDeviceCode)
	}
	return grantTypes
}

func SubjectTypes(c Configuration) []string {
	return []string{"public"} // TODO: config
}

func SigAlgorithms(ctx context.Context, storage DiscoverStorage) []string {
	ctx, span := Tracer.Start(ctx, "SigAlgorithms")
	defer span.End()

	algorithms, err := storage.SignatureAlgorithms(ctx)
	if err != nil {
		return nil
	}
	return algorithms
}

func RequestObjectSigAlgorithms(c Configuration) []string {
	if !c.RequestObjectSupported() {
		return nil
	}
	return c.RequestObjectSigningAlgorithmsSupported()
}

func AuthMethodsTokenEndpoint(c Configuration) []oidc.AuthMethod {
	authMethods := []oidc.AuthMethod{
		oidc.AuthMethodNone,
		oidc.AuthMethodBasic,
	}
	if c.AuthMethodPostSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPost)
	}
	if c.AuthMethodPrivateKeyJWTSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPrivateKeyJWT)
	}
	return authMethods
}

func TokenSigAlgorithms(c Configuration) []string {
	if !c.AuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.TokenEndpointSigningAlgorithmsSupported()
}

func IntrospectionSigAlgorithms(c Configuration) []string {
	if !c.IntrospectionAuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.IntrospectionEndpointSigningAlgorithmsSupported()
}

func AuthMethodsIntrospectionEndpoint(c Configuration) []oidc.AuthMethod {
	authMethods := []oidc.AuthMethod{
		oidc.AuthMethodBasic,
	}
	if c.AuthMethodPrivateKeyJWTSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPrivateKeyJWT)
	}
	return authMethods
}

func RevocationSigAlgorithms(c Configuration) []string {
	if !c.RevocationAuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.RevocationEndpointSigningAlgorithmsSupported()
}

func AuthMethodsRevocationEndpoint(c Configuration) []oidc.AuthMethod {
	authMethods := []oidc.AuthMethod{
		oidc.AuthMethodNone,
		oidc.AuthMethodBasic,
	}
	if c.AuthMethodPostSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPost)
	}
	if c.AuthMethodPrivateKeyJWTSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPrivateKeyJWT)
	}
	return authMethods
}

func SupportedClaims(c Configuration) []string {
	provider, ok := c.(*Provider)
	if ok && provider.config.SupportedClaims != nil {
		return provider.config.SupportedClaims
	}

	return DefaultSupportedClaims
}

func IDTokenEncryptionAlgValues(c Configuration) []string {
	provider, ok := c.(*Provider)
	if !ok {
		return nil
	}
	cr := provider.Crypto()
	if cr == nil {
		return nil
	}

	var algs []string
	if _, ok := cr.(TokenEncryptionKeyProvider); ok {
		algs = append(algs, oidc.JWEAlgDir)
	}
	if _, ok := cr.(SM2TokenEncryptionPublicKeyProvider); ok {
		algs = append(algs, oidc.JWEAlgSM23)
	}
	if _, ok := cr.(SM9TokenEncryptionPublicKeyProvider); ok {
		algs = append(algs, oidc.JWEAlgSM93)
	}
	if len(algs) == 0 {
		return nil
	}
	return algs
}

func IDTokenEncryptionEncValues(c Configuration) []string {
	provider, ok := c.(*Provider)
	if !ok {
		return nil
	}
	cr := provider.Crypto()
	if cr == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var encs []string
	addEnc := func(enc string) {
		if _, ok := seen[enc]; !ok {
			seen[enc] = struct{}{}
			encs = append(encs, enc)
		}
	}

	if _, ok := cr.(TokenEncryptionKeyProvider); ok {
		addEnc(oidc.JWEEncSM4GCM)
		addEnc(oidc.JWEEncA256GCM)
		addEnc(oidc.JWEEncA128GCM)
	}
	if _, ok := cr.(SM2TokenEncryptionPublicKeyProvider); ok {
		addEnc(oidc.JWEEncSM4GCM)
	}
	if _, ok := cr.(SM9TokenEncryptionPublicKeyProvider); ok {
		addEnc(oidc.JWEEncSM4GCM)
	}
	if len(encs) == 0 {
		return nil
	}
	return encs
}

func CodeChallengeMethods(c Configuration) []oidc.CodeChallengeMethod {
	codeMethods := make([]oidc.CodeChallengeMethod, 0, 1)
	if c.CodeMethodS256Supported() {
		codeMethods = append(codeMethods, oidc.CodeChallengeMethodS256)
	}
	return codeMethods
}
