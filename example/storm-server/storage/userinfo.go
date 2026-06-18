// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"fmt"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// =================================================================
// storm.IntrospectStore
// =================================================================

func (s *Storage) SetIntrospectionFromToken(_ context.Context, resp *protocol.IntrospectionResponse, tokenID, subject, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		for _, rt := range s.refreshTokens {
			if rt.Token == tokenID {
				token = &Token{
					ID:            tokenID,
					ApplicationID: rt.ApplicationID,
					Subject:       rt.UserID,
					Audience:      rt.Audience,
					Expiration:    rt.Expiration,
					Scopes:        rt.Scopes,
				}
				break
			}
		}
		if token == nil {
			return fmt.Errorf("token not found")
		}
	}

	resp.Active = true
	resp.ClientID = token.ApplicationID
	resp.Subject = token.Subject
	resp.Audience = token.Audience
	resp.Scope = protocol.SpaceDelimitedArray(token.Scopes)
	resp.TokenType = protocol.BearerToken
	if !token.Expiration.IsZero() {
		resp.Expiration = protocol.FromTime(token.Expiration)
		resp.NotBefore = protocol.FromTime(token.Expiration)
	}
	if token.CNF != nil {
		if resp.Claims == nil {
			resp.Claims = make(map[string]any)
		}
		resp.Claims["cnf"] = token.CNF
	}

	return nil
}

// =================================================================
// storm.UserinfoStore
// =================================================================

func (s *Storage) SetUserinfoFromToken(_ context.Context, userinfo *protocol.UserInfo, tokenID, subject, origin string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		// check refresh tokens
		for _, rt := range s.refreshTokens {
			if rt.Token == tokenID {
				token = &Token{
					ID:            tokenID,
					ApplicationID: rt.ApplicationID,
					Subject:       rt.UserID,
					Audience:      rt.Audience,
					Expiration:    rt.Expiration,
					Scopes:        rt.Scopes,
				}
				break
			}
		}
		if token == nil {
			return fmt.Errorf("token not found")
		}
	}

	user := s.userStore.GetUserByID(token.Subject)
	if user == nil {
		// Fallback: subject may be a username (e.g. from CIBA login_hint).
		user = s.userStore.GetUserByUsername(token.Subject)
	}
	if user == nil {
		// client_credentials grant: subject is the client ID, not a real user.
		// Return a minimal response with just the "sub" claim so the resource
		// endpoint test receives HTTP 200 instead of 401.
		userinfo.Subject = token.Subject
		return nil
	}

	// OIDC Core §5.3.2: "sub" claim MUST always be returned in the UserInfo response.
	// This is a MUST-level requirement, not gated by scope.
	userinfo.Subject = user.ID

	for _, scope := range token.Scopes {
		switch scope {
		case protocol.ScopeOpenID:
			// No additional claims beyond "sub" for the openid scope alone.
		case protocol.ScopeEmail:
			userinfo.Email = user.Email
			userinfo.EmailVerified = protocol.Bool(user.EmailVerified)
		case protocol.ScopeProfile:
			userinfo.PreferredUsername = user.Username
			userinfo.Name = user.FirstName + " " + user.LastName
			userinfo.FamilyName = user.LastName
			userinfo.GivenName = user.FirstName
			userinfo.Nickname = user.Username
			userinfo.Locale = protocol.NewLocale(user.PreferredLanguage)
			userinfo.Zoneinfo = "UTC"
			userinfo.UpdatedAt = protocol.Time(user.UpdatedAt)
			userinfo.AppendClaims("middle_name", "N/A")
			userinfo.AppendClaims("profile", "https://example.com")
			userinfo.AppendClaims("picture", "https://example.com/avatar.png")
			userinfo.AppendClaims("website", "https://example.com")
			userinfo.AppendClaims("gender", "other")
			userinfo.AppendClaims("birthdate", "2000-01-01")
		case protocol.ScopeAddress:
			userinfo.Address = &protocol.UserInfoAddress{
				Formatted: "N/A",
			}
		case protocol.ScopePhone:
			userinfo.PhoneNumber = user.Phone
			userinfo.PhoneNumberVerified = protocol.Bool(user.PhoneVerified)
		}
	}

	// Scope-based filtering per OIDC Core §5.4.
	userinfo.FilterByScopes(token.Scopes)

	// OIDC Core §5.5: claims parameter can request specific claims
	// even without the corresponding scope.
	if token.Claims != nil && token.Claims.UserInfo != nil {
		applyUserInfoClaims(userinfo, user, token.Claims.UserInfo)
	}

	return nil
}

// applyUserInfoClaims applies claims requested via the OIDC §5.5 claims parameter
// to the UserInfo response.
func applyUserInfoClaims(userinfo *protocol.UserInfo, user *User, claims map[string]*protocol.ClaimRequest) {
	for name := range claims {
		switch name {
		case "name":
			userinfo.Name = user.FirstName + " " + user.LastName
		case "given_name":
			userinfo.GivenName = user.FirstName
		case "family_name":
			userinfo.FamilyName = user.LastName
		case "middle_name":
			userinfo.AppendClaims("middle_name", "N/A")
		case "nickname":
			userinfo.Nickname = user.Username
		case "preferred_username":
			userinfo.PreferredUsername = user.Username
		case "profile":
			userinfo.AppendClaims("profile", "https://example.com")
		case "picture":
			userinfo.AppendClaims("picture", "https://example.com/avatar.png")
		case "website":
			userinfo.AppendClaims("website", "https://example.com")
		case "email":
			userinfo.Email = user.Email
			userinfo.EmailVerified = protocol.Bool(user.EmailVerified)
		case "gender":
			userinfo.AppendClaims("gender", "other")
		case "birthdate":
			userinfo.AppendClaims("birthdate", "2000-01-01")
		case "zoneinfo":
			userinfo.Zoneinfo = "UTC"
		case "locale":
			userinfo.Locale = protocol.NewLocale(user.PreferredLanguage)
		case "phone_number":
			userinfo.PhoneNumber = user.Phone
			userinfo.PhoneNumberVerified = protocol.Bool(user.PhoneVerified)
		case "address":
			userinfo.Address = &protocol.UserInfoAddress{
				Formatted: "N/A",
			}
		case "updated_at":
			userinfo.UpdatedAt = protocol.Time(user.UpdatedAt)
		}
	}
}
