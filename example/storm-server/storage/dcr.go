// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// =================================================================
// storm.DCRStore (Dynamic Client Registration)
// =================================================================

func (s *Storage) CreateClient(_ context.Context, req *storm.RegistrationRequest, clientID, clientSecret, accessToken, uri string) (*storm.ClientRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Store the registered client
	var responseTypes []protocol.ResponseType
	if len(req.ResponseTypes) > 0 {
		for _, rt := range req.ResponseTypes {
			responseTypes = append(responseTypes, protocol.ResponseType(rt))
		}
	} else {
		responseTypes = []protocol.ResponseType{protocol.ResponseTypeCode}
	}
	var grantTypes []protocol.GrantType
	if len(req.GrantTypes) > 0 {
		for _, gt := range req.GrantTypes {
			grantTypes = append(grantTypes, protocol.GrantType(gt))
		}
		// Per OIDC Core, authorization_code grant implies refresh_token support.
		hasCode := slices.Contains(grantTypes, protocol.GrantTypeCode)
		hasRefresh := slices.Contains(grantTypes, protocol.GrantTypeRefreshToken)
		if hasCode && !hasRefresh {
			grantTypes = append(grantTypes, protocol.GrantTypeRefreshToken)
		}
	} else {
		grantTypes = []protocol.GrantType{protocol.GrantTypeCode, protocol.GrantTypeRefreshToken}
	}
	// Parse keys from jwks field if present.
	// Per OIDC Core §10.1, match by kid (if specified in request) and use=enc.
	// Note: jwks_uri is not resolved here; the DCR plugin layer should fetch
	// and merge into jwks before calling CreateClient.
	var encKey interface{}
	var sigKeys []jwk.Key
	if len(req.JWKS) > 0 {
		set, err := jwk.Parse(req.JWKS)
		if err == nil {
			targetAlg := req.IDTokenEncryptedResponseAlg
			for i := range set.Len() {
				key, _ := set.Key(i)
				// Collect all keys for signature verification (JWT Bearer Grant)
				sigKeys = append(sigKeys, key)
				// Filter by use=enc if present for encryption key
				if ku, ok := key.KeyUsage(); ok && ku != "" && ku != "enc" {
					continue
				}
				// Filter by alg if specified
				if targetAlg != "" {
					if ka, ok := key.Algorithm(); !ok || ka.String() != targetAlg {
						continue
					}
				}
				encKey = key
				break
			}
		}
	}

	// Determine client authentication method from registration request.
	// Default to client_secret_basic per RFC 7591 §2.
	authMethod := protocol.AuthMethodBasic
	if req.TokenEndpointAuthMethod != "" {
		authMethod = protocol.AuthMethod(req.TokenEndpointAuthMethod)
	}

	client := &Client{
		id:                        clientID,
		secret:                    clientSecret,
		redirectURIs:              req.RedirectURIs,
		authMethod:                authMethod,
		loginURLFn:                defaultLoginURL,
		responseTypes:             responseTypes,
		grantTypes:                grantTypes,
		postLogoutRedirectURIs:    req.PostLogoutRedirectURIs,
		backChannelLogoutURI:      req.BackChannelLogoutURI,
		logoURI:                   req.LogoURI,
		policyURI:                 req.PolicyURI,
		tosURI:                    req.TOSURI,
		sectorIdentifierURI:       req.SectorIdentifierURI,
		idTokenEncryptionAlg:      req.IDTokenEncryptedResponseAlg,
		idTokenEncryptionEnc:      req.IDTokenEncryptedResponseEnc,
		clientEncryptionKey:       encKey,
		clientJWKS:                sigKeys,
		jwksURI:                   req.JWKSURI,
		userInfoSignedResponseAlg: req.UserInfoSignedResponseAlg,
		idTokenSignedResponseAlg:  req.IDTokenSignedResponseAlg,
		requestObjectSigningAlg:   req.RequestObjectSigningAlg,
		requireDPoP:               req.RequireDPoP,
		requireMtls:               req.RequireMtls,
	}
	s.clients[clientID] = client

	// Build grant_types list from the actual (possibly augmented) grantTypes slice
	grantTypesStr := make([]string, len(grantTypes))
	for i, gt := range grantTypes {
		grantTypesStr[i] = string(gt)
	}

	reg := &storm.ClientRegistration{
		ClientID:                     clientID,
		ClientSecret:                 clientSecret,
		RegistrationAccessToken:      accessToken,
		RegistrationClientURI:        uri,
		ClientIDIssuedAt:             time.Now().Unix(),
		ClientSecretExpiresAt:        0,
		ApplicationType:              req.ApplicationType,
		ClientName:                   req.ClientName,
		RedirectURIs:                 req.RedirectURIs,
		ResponseTypes:                req.ResponseTypes,
		GrantTypes:                   grantTypesStr,
		TokenEndpointAuthMethod:      req.TokenEndpointAuthMethod,
		Scope:                        req.Scope,
		JWKSURI:                      req.JWKSURI,
		JWKS:                         req.JWKS,
		PostLogoutRedirectURIs:       req.PostLogoutRedirectURIs,
		BackChannelLogoutURI:         req.BackChannelLogoutURI,
		LogoURI:                      req.LogoURI,
		PolicyURI:                    req.PolicyURI,
		TOSURI:                       req.TOSURI,
		SectorIdentifierURI:          req.SectorIdentifierURI,
		InitiateLoginURI:             req.InitiateLoginURI,
		IDTokenEncryptedResponseAlg:  req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  req.IDTokenEncryptedResponseEnc,
		IDTokenSignedResponseAlg:     req.IDTokenSignedResponseAlg,
		UserInfoSignedResponseAlg:    req.UserInfoSignedResponseAlg,
		UserInfoEncryptedResponseAlg: req.UserInfoEncryptedResponseAlg,
		UserInfoEncryptedResponseEnc: req.UserInfoEncryptedResponseEnc,
		RequestObjectSigningAlg:      req.RequestObjectSigningAlg,
		RequireDPoP:                  req.RequireDPoP,
		RequireMtls:                  req.RequireMtls,
	}

	// Store registration data for later lookup
	s.registrationTokens[accessToken] = clientID
	s.registrations[clientID] = reg

	return reg, nil
}

func (s *Storage) GetClientRegistration(_ context.Context, clientID string) (*storm.ClientRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	reg, ok := s.registrations[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	return reg, nil
}

func (s *Storage) GetClientRegistrationByToken(_ context.Context, token string) (*storm.ClientRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	clientID, ok := s.registrationTokens[token]
	if !ok {
		return nil, fmt.Errorf("no client found for token")
	}

	reg, ok := s.registrations[clientID]
	if !ok {
		return nil, fmt.Errorf("no client found for token")
	}

	return reg, nil
}

func (s *Storage) UpdateClientRegistration(_ context.Context, clientID string, update *storm.RegistrationRequest) (*storm.ClientRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	client, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	reg, ok := s.registrations[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	if len(update.RedirectURIs) > 0 {
		client.redirectURIs = update.RedirectURIs
		reg.RedirectURIs = update.RedirectURIs
	}
	if update.InitiateLoginURI != "" {
		reg.InitiateLoginURI = update.InitiateLoginURI
	}

	return reg, nil
}

func (s *Storage) DeleteClientRegistration(_ context.Context, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Remove the registration token
	reg, ok := s.registrations[clientID]
	if ok && reg.RegistrationAccessToken != "" {
		delete(s.registrationTokens, reg.RegistrationAccessToken)
	}

	delete(s.registrations, clientID)
	delete(s.clients, clientID)
	return nil
}
