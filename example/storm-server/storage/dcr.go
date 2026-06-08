// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"fmt"
	"time"

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
	} else {
		grantTypes = []protocol.GrantType{protocol.GrantTypeCode, protocol.GrantTypeRefreshToken}
	}
	client := &Client{
		id:                     clientID,
		secret:                 clientSecret,
		redirectURIs:           req.RedirectURIs,
		authMethod:             protocol.AuthMethodBasic,
		loginURLFn:             defaultLoginURL,
		responseTypes:          responseTypes,
		grantTypes:             grantTypes,
		postLogoutRedirectURIs: req.PostLogoutRedirectURIs,
		backChannelLogoutURI:   req.BackChannelLogoutURI,
	}
	s.clients[clientID] = client

	reg := &storm.ClientRegistration{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		RegistrationAccessToken: accessToken,
		RegistrationClientURI:   uri,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0,
		ApplicationType:         req.ApplicationType,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		ResponseTypes:           req.ResponseTypes,
		GrantTypes:              req.GrantTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scope:                   req.Scope,
		JWKSURI:                 req.JWKSURI,
		JWKS:                    req.JWKS,
		PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
		BackChannelLogoutURI:    req.BackChannelLogoutURI,
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
