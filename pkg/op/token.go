// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package op

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
)

type TokenCreator interface {
	Storage() Storage
	Crypto() Crypto
}

type TokenRequest interface {
	GetSubject() string
	GetAudience() []string
	GetScopes() []string
}

type AccessTokenClient interface {
	GetID() string
	ClockSkew() time.Duration
	RestrictAdditionalAccessTokenScopes() func(scopes []string) []string
	GrantTypes() []oidc.GrantType
}

func CreateTokenResponse(ctx context.Context, request IDTokenRequest, client Client, creator TokenCreator, createAccessToken bool, code, refreshToken string) (*oidc.AccessTokenResponse, error) {
	ctx, span := Tracer.Start(ctx, "CreateTokenResponse")
	defer span.End()

	var accessToken, newRefreshToken string
	var validity time.Duration
	if createAccessToken {
		var err error
		accessToken, newRefreshToken, validity, err = CreateAccessToken(ctx, request, client.AccessTokenType(), creator, client, refreshToken)
		if err != nil {
			return nil, err
		}
	}
	idToken, err := CreateIDToken(ctx, IssuerFromContext(ctx), request, client.IDTokenLifetime(), accessToken, code, creator.Storage(), client)
	if err != nil {
		return nil, err
	}

	// Optionally encrypt the ID token if the client supports it.
	if encClient, ok := client.(IDTokenEncryptionClient); ok {
		if alg, enc := encClient.IDTokenEncryptionAlg(), encClient.IDTokenEncryptionEnc(); alg != "" && enc != "" {
			encrypted, err := encryptIDToken(idToken, creator.Crypto(), alg, enc)
			if err != nil {
				return nil, err
			}
			idToken = encrypted
		}
	}

	var state string
	if authRequest, ok := request.(AuthRequest); ok {
		err = creator.Storage().DeleteAuthRequest(ctx, authRequest.GetID())
		if err != nil {
			return nil, err
		}
		// only implicit flow requires state to be returned.
		if code == "" {
			state = authRequest.GetState()
		}
	}

	exp := uint64(validity.Seconds())
	return &oidc.AccessTokenResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: newRefreshToken,
		TokenType:    oidc.BearerToken,
		ExpiresIn:    exp,
		State:        state,
		Scope:        request.GetScopes(),
	}, nil
}

// createTokens delegates token creation to the appropriate storage method based on
// the request type and requirements. It returns an access token ID and expiration
// in all cases, but the refresh token handling varies:
//   - When needsRefreshToken() returns true: calls CreateAccessAndRefreshTokens,
//     which returns both tokens. The newRefreshToken will contain the actual token value.
//   - When needsRefreshToken() returns false: calls CreateAccessToken only.
//     The newRefreshToken will be an empty string in this case.
func createTokens(ctx context.Context, tokenRequest TokenRequest, storage Storage, refreshToken string, client AccessTokenClient) (id, newRefreshToken string, exp time.Time, err error) {
	ctx, span := Tracer.Start(ctx, "createTokens")
	defer span.End()

	if needsRefreshToken(tokenRequest, client) {
		return storage.CreateAccessAndRefreshTokens(ctx, tokenRequest, refreshToken)
	}
	id, exp, err = storage.CreateAccessToken(ctx, tokenRequest)
	return id, "", exp, err
}

func needsRefreshToken(tokenRequest TokenRequest, client AccessTokenClient) bool {
	switch req := tokenRequest.(type) {
	case AuthRequest:
		return slices.Contains(req.GetScopes(), oidc.ScopeOfflineAccess) && req.GetResponseType() == oidc.ResponseTypeCode && ValidateGrantType(client, oidc.GrantTypeRefreshToken)
	case TokenExchangeRequest:
		return req.GetRequestedTokenType() == oidc.RefreshTokenType
	case RefreshTokenRequest:
		return true
	case *DeviceAuthorizationState:
		return slices.Contains(req.GetScopes(), oidc.ScopeOfflineAccess) && ValidateGrantType(client, oidc.GrantTypeRefreshToken)
	default:
		return false
	}
}

// CreateAccessToken creates an access token and may return a refresh token from storage.
// This function always creates the access token using the ID returned from storage.
// The refresh token is obtained from the storage layer and passed through unchanged.
// Whether a refresh token is included depends on the request:
//   - Authorization code flow with offline_access scope: returns refresh token
//   - Refresh token grant (rotation): returns new refresh token
//   - Client credentials, implicit flow: returns empty string
//
// The function returns both tokens to support all flows with a single signature.
func CreateAccessToken(ctx context.Context, tokenRequest TokenRequest, accessTokenType AccessTokenType, creator TokenCreator, client AccessTokenClient, refreshToken string) (accessToken, newRefreshToken string, validity time.Duration, err error) {
	ctx, span := Tracer.Start(ctx, "CreateAccessToken")
	defer span.End()

	id, newRefreshToken, exp, err := createTokens(ctx, tokenRequest, creator.Storage(), refreshToken, client)
	if err != nil {
		return "", "", 0, err
	}
	var clockSkew time.Duration
	if client != nil {
		clockSkew = client.ClockSkew()
	}
	validity = exp.Add(clockSkew).Sub(time.Now().UTC())
	if accessTokenType == AccessTokenTypeJWT {
		accessToken, err = CreateJWT(ctx, IssuerFromContext(ctx), tokenRequest, exp, id, client, creator.Storage())
		return accessToken, newRefreshToken, validity, err
	}
	_, span = Tracer.Start(ctx, "CreateBearerToken")
	accessToken, err = CreateBearerToken(id, tokenRequest.GetSubject(), creator.Crypto())
	span.End()
	return accessToken, newRefreshToken, validity, err
}

func CreateBearerToken(tokenID, subject string, crypto Encrypter) (string, error) {
	return crypto.Encrypt(tokenID + ":" + subject)
}

type TokenActorRequest interface {
	GetActor() *oidc.ActorClaims
}

func CreateJWT(ctx context.Context, issuer string, tokenRequest TokenRequest, exp time.Time, id string, client AccessTokenClient, storage Storage) (string, error) {
	ctx, span := Tracer.Start(ctx, "CreateJWT")
	defer span.End()

	claims := oidc.NewAccessTokenClaims(issuer, tokenRequest.GetSubject(), tokenRequest.GetAudience(), exp, id, client.GetID(), client.ClockSkew())
	if client != nil {
		restrictedScopes := client.RestrictAdditionalAccessTokenScopes()(tokenRequest.GetScopes())

		var (
			privateClaims map[string]any
			err           error
		)

		tokenExchangeRequest, okReq := tokenRequest.(TokenExchangeRequest)
		teStorage, okStorage := storage.(TokenExchangeStorage)
		if okReq && okStorage {
			privateClaims, err = teStorage.GetPrivateClaimsFromTokenExchangeRequest(
				ctx,
				tokenExchangeRequest,
			)
		} else {
			if fromRequest, ok := storage.(CanGetPrivateClaimsFromRequest); ok {
				privateClaims, err = fromRequest.GetPrivateClaimsFromRequest(ctx, tokenRequest, removeUserinfoScopes(restrictedScopes))
			} else {
				privateClaims, err = storage.GetPrivateClaimsFromScopes(ctx, tokenRequest.GetSubject(), client.GetID(), removeUserinfoScopes(restrictedScopes))
			}
		}

		if err != nil {
			return "", err
		}
		claims.Claims = privateClaims
	}
	if actorReq, ok := tokenRequest.(TokenActorRequest); ok {
		claims.Actor = actorReq.GetActor()
	}
	signingKey, err := storage.SigningKey(ctx)
	if err != nil {
		return "", err
	}
	signer, err := SignerFromKey(signingKey)
	if err != nil {
		return "", err
	}
	return crypto.Sign(claims, signer)
}

type IDTokenRequest interface {
	GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetScopes() []string
	GetSubject() string
}

func CreateIDToken(ctx context.Context, issuer string, request IDTokenRequest, validity time.Duration, accessToken, code string, storage Storage, client Client) (string, error) {
	ctx, span := Tracer.Start(ctx, "CreateIDToken")
	defer span.End()

	exp := time.Now().UTC().Add(client.ClockSkew()).Add(validity)
	var acr, nonce string
	if authRequest, ok := request.(AuthRequest); ok {
		acr = authRequest.GetACR()
		nonce = authRequest.GetNonce()
	}
	claims := oidc.NewIDTokenClaims(issuer, request.GetSubject(), request.GetAudience(), exp, request.GetAuthTime(), nonce, acr, request.GetAMR(), request.GetClientID(), client.ClockSkew())
	if actorReq, ok := request.(TokenActorRequest); ok {
		claims.Actor = actorReq.GetActor()
	}

	scopes := client.RestrictAdditionalIdTokenScopes()(request.GetScopes())
	signingKey, err := storage.SigningKey(ctx)
	if err != nil {
		return "", err
	}
	if accessToken != "" {
		atHash, err := oidc.ClaimHash(accessToken, signingKey.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
		claims.AccessTokenHash = atHash
		if !client.IDTokenUserinfoClaimsAssertion() {
			scopes = removeUserinfoScopes(scopes)
		}
	}

	tokenExchangeRequest, okReq := request.(TokenExchangeRequest)
	teStorage, okStorage := storage.(TokenExchangeStorage)
	if okReq && okStorage {
		userInfo := new(oidc.UserInfo)
		err := teStorage.SetUserinfoFromTokenExchangeRequest(ctx, userInfo, tokenExchangeRequest)
		if err != nil {
			return "", err
		}
		claims.SetUserInfo(userInfo)
	} else if len(scopes) > 0 {
		userInfo := new(oidc.UserInfo)
		if fromRequest, ok := storage.(CanSetUserinfoFromRequest); ok {
			err := fromRequest.SetUserinfoFromRequest(ctx, userInfo, request, scopes)
			if err != nil {
				return "", err
			}
		}
		claims.SetUserInfo(userInfo)
	}
	if code != "" {
		codeHash, err := oidc.ClaimHash(code, signingKey.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
		claims.CodeHash = codeHash
	}
	signer, err := SignerFromKey(signingKey)
	if err != nil {
		return "", err
	}
	return crypto.Sign(claims, signer)
}

func removeUserinfoScopes(scopes []string) []string {
	newScopeList := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeProfile,
			oidc.ScopeEmail,
			oidc.ScopeAddress,
			oidc.ScopePhone:
			continue
		default:
			newScopeList = append(newScopeList, scope)
		}
	}
	return newScopeList
}

// encryptIDToken encrypts a signed ID token (JWS compact) into a JWE compact
// based on the requested key management algorithm (alg) and content encryption
// algorithm (enc).
//
// Supported key management algorithms:
//   - "dir": Direct symmetric encryption (requires TokenEncryptionKeyProvider)
//   - "A256GCMKW": Standard AES-256 GCM key wrapping
//   - "SGD_SM2_3": SM2 public-key key wrapping (requires SM2TokenEncryptionPublicKeyProvider)
//   - "SGD_SM9_3": SM9 identity-based key wrapping (requires SM9TokenEncryptionPublicKeyProvider)
//
// Supported content encryption methods:
//   - "SGD_SM4_GCM": SM4-GCM (GM/T 0125.3)
//   - "A256GCM": AES-256-GCM
//   - "A128GCM": AES-128-GCM
func encryptIDToken(signedToken string, c Crypto, alg, enc string) (string, error) {
	switch alg {
	case oidc.JWEAlgDir:
		keyProvider, ok := c.(TokenEncryptionKeyProvider)
		if !ok || keyProvider.TokenEncryptionKey() == nil {
			return "", fmt.Errorf("token encryption requested but Crypto does not implement TokenEncryptionKeyProvider")
		}
		key := keyProvider.TokenEncryptionKey()
		switch enc {
		case oidc.JWEEncSM4GCM:
			return oidc.EncryptToken(signedToken, key)
		case oidc.JWEEncA256GCM:
			return oidc.EncryptTokenA256GCM(signedToken, key)
		case oidc.JWEEncA128GCM:
			return oidc.EncryptTokenA128GCM(signedToken, key)
		default:
			return "", fmt.Errorf("unsupported JWE content encryption: %s", enc)
		}
	case oidc.JWEAlgSM23:
		pkProvider, ok := c.(SM2TokenEncryptionPublicKeyProvider)
		if !ok || pkProvider.SM2TokenEncryptionPublicKey() == nil {
			return "", fmt.Errorf("SM2 encryption requested but Crypto does not implement SM2TokenEncryptionPublicKeyProvider")
		}
		return oidc.EncryptTokenSM2(signedToken, pkProvider.SM2TokenEncryptionPublicKey())
	case oidc.JWEAlgSM93:
		pkProvider, ok := c.(SM9TokenEncryptionPublicKeyProvider)
		if !ok || pkProvider.SM9TokenEncryptionMasterPublicKey() == nil {
			return "", fmt.Errorf("SM9 encryption requested but Crypto does not implement SM9TokenEncryptionPublicKeyProvider")
		}
		return oidc.EncryptTokenSM9(signedToken, pkProvider.SM9TokenEncryptionMasterPublicKey(), pkProvider.SM9TokenEncryptionUID())
	default:
		return "", fmt.Errorf("unsupported JWE key management algorithm: %s", alg)
	}
}
