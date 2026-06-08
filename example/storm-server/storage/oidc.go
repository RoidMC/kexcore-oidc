// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package storage

import (
	"log/slog"
	"time"

	"golang.org/x/text/language"

	"github.com/google/uuid"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

const (
	CustomScope                  = "custom_scope"
	CustomClaim                  = "custom_claim"
	CustomScopeImpersonatePrefix = "custom_scope:impersonate:"
)

type AuthRequest struct {
	ID            string
	CreationDate  time.Time
	ApplicationID string
	CallbackURI   string
	TransferState string
	Prompt        []string
	UiLocales     []language.Tag
	LoginHint     string
	MaxAuthAge    *time.Duration
	UserID        string
	Scopes        []string
	ResponseType  protocol.ResponseType
	ResponseMode  protocol.ResponseMode
	Nonce         string
	CodeChallenge *OIDCCodeChallenge
	ACRValues     []string
	Claims        *protocol.ClaimsRequest

	// extraIDTokenClaims holds claims requested via claims.id_token (OIDC §5.5)
	// that should be merged into the ID token.
	extraIDTokenClaims map[string]any

	done      bool
	authTime  time.Time
	sessionID string
	acr       string
}

func (a *AuthRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", a.ID),
		slog.Time("creation_date", a.CreationDate),
		slog.Any("scopes", a.Scopes),
		slog.String("response_type", string(a.ResponseType)),
		slog.String("app_id", a.ApplicationID),
		slog.String("callback_uri", a.CallbackURI),
	)
}

func (a *AuthRequest) GetID() string { return a.ID }
func (a *AuthRequest) GetACR() string {
	if a.done && a.acr != "" {
		return a.acr
	}
	if len(a.ACRValues) > 0 {
		return a.ACRValues[0]
	}
	return ""
}
func (a *AuthRequest) GetAMR() []string {
	if a.done {
		return []string{"pwd"}
	}
	return nil
}
func (a *AuthRequest) GetAudience() []string  { return []string{a.ApplicationID} }
func (a *AuthRequest) GetAuthTime() time.Time { return a.authTime }
func (a *AuthRequest) GetClientID() string    { return a.ApplicationID }
func (a *AuthRequest) GetCodeChallenge() *protocol.CodeChallenge {
	return CodeChallengeToOIDC(a.CodeChallenge)
}
func (a *AuthRequest) GetNonce() string                       { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string                 { return a.CallbackURI }
func (a *AuthRequest) GetResponseType() protocol.ResponseType { return a.ResponseType }
func (a *AuthRequest) GetResponseMode() protocol.ResponseMode { return a.ResponseMode }
func (a *AuthRequest) GetScopes() []string                    { return a.Scopes }
func (a *AuthRequest) GetState() string                       { return a.TransferState }
func (a *AuthRequest) GetSubject() string                     { return a.UserID }
func (a *AuthRequest) GetClaims() *protocol.ClaimsRequest     { return a.Claims }
func (a *AuthRequest) Done() bool                             { return a.done }

// ExtraIDTokenClaims implements idTokenClaimsExtender for the token plugin.
// Returns claims requested via the OIDC §5.5 claims.id_token parameter.
func (a *AuthRequest) ExtraIDTokenClaims() map[string]any {
	return a.extraIDTokenClaims
}
func (a *AuthRequest) GetSID() string { return a.sessionID }

func PromptToInternal(oidcPrompt protocol.SpaceDelimitedArray) []string {
	prompts := make([]string, 0, len(oidcPrompt))
	for _, p := range oidcPrompt {
		switch p {
		case protocol.PromptNone, protocol.PromptLogin, protocol.PromptConsent, protocol.PromptSelectAccount:
			prompts = append(prompts, p)
		}
	}
	return prompts
}

func MaxAgeToInternal(maxAge *uint) *time.Duration {
	if maxAge == nil {
		return nil
	}
	dur := time.Duration(*maxAge) * time.Second
	return &dur
}

func authRequestToInternal(authReq *protocol.AuthRequest, userID string, user *User) *AuthRequest {
	var codeChallenge *OIDCCodeChallenge
	if authReq.CodeChallenge != "" {
		codeChallenge = &OIDCCodeChallenge{
			Challenge: authReq.CodeChallenge,
			Method:    string(authReq.CodeChallengeMethod),
		}
	}
	return &AuthRequest{
		CreationDate:       time.Now(),
		ApplicationID:      authReq.ClientID,
		CallbackURI:        authReq.RedirectURI,
		TransferState:      authReq.State,
		Prompt:             PromptToInternal(authReq.Prompt),
		UiLocales:          authReq.UILocales,
		LoginHint:          authReq.LoginHint,
		MaxAuthAge:         MaxAgeToInternal(authReq.MaxAge),
		UserID:             userID,
		Scopes:             authReq.Scopes,
		ResponseType:       authReq.ResponseType,
		ResponseMode:       authReq.ResponseMode,
		Nonce:              authReq.Nonce,
		CodeChallenge:      codeChallenge,
		ACRValues:          authReq.ACRValues,
		Claims:             authReq.Claims,
		extraIDTokenClaims: buildIDTokenClaims(authReq.Claims, user),
		sessionID:          uuid.NewString(),
	}
}

// buildIDTokenClaims returns extra claims to merge into the ID token
// based on the OIDC §5.5 claims.id_token request parameter.
func buildIDTokenClaims(cr *protocol.ClaimsRequest, user *User) map[string]any {
	if cr == nil || cr.IDToken == nil || user == nil {
		return nil
	}
	claims := make(map[string]any)
	for name := range cr.IDToken {
		switch name {
		case "auth_time", "acr", "amr", "azp":
			// Handled directly by the token plugin; skip.
		case "name":
			claims["name"] = user.FirstName + " " + user.LastName
		case "given_name":
			claims["given_name"] = user.FirstName
		case "family_name":
			claims["family_name"] = user.LastName
		case "middle_name":
			claims["middle_name"] = "N/A"
		case "nickname":
			claims["nickname"] = user.Username
		case "preferred_username":
			claims["preferred_username"] = user.Username
		case "profile":
			claims["profile"] = "https://example.com"
		case "picture":
			claims["picture"] = "https://example.com/avatar.png"
		case "website":
			claims["website"] = "https://example.com"
		case "email":
			claims["email"] = user.Email
			claims["email_verified"] = user.EmailVerified
		case "gender":
			claims["gender"] = "other"
		case "birthdate":
			claims["birthdate"] = "2000-01-01"
		case "zoneinfo":
			claims["zoneinfo"] = "UTC"
		case "locale":
			claims["locale"] = user.PreferredLanguage
		case "phone_number":
			claims["phone_number"] = user.Phone
			claims["phone_number_verified"] = user.PhoneVerified
		case "address":
			claims["address"] = map[string]string{"formatted": "N/A"}
		case "updated_at":
			claims["updated_at"] = time.Now().Unix()
		}
	}
	if len(claims) == 0 {
		return nil
	}
	return claims
}

type OIDCCodeChallenge struct {
	Challenge string
	Method    string
}

func CodeChallengeToOIDC(challenge *OIDCCodeChallenge) *protocol.CodeChallenge {
	if challenge == nil {
		return nil
	}
	method := protocol.CodeChallengeMethodPlain
	if challenge.Method == "S256" {
		method = protocol.CodeChallengeMethodS256
	}
	return &protocol.CodeChallenge{Challenge: challenge.Challenge, Method: method}
}

// RefreshTokenRequest wraps a RefreshToken to implement storm.RefreshTokenRequest.
type RefreshTokenRequest struct {
	*RefreshToken
}

func (r *RefreshTokenRequest) GetAMR() []string                          { return r.AMR }
func (r *RefreshTokenRequest) GetAudience() []string                     { return r.Audience }
func (r *RefreshTokenRequest) GetAuthTime() time.Time                    { return r.AuthTime }
func (r *RefreshTokenRequest) GetClientID() string                       { return r.ApplicationID }
func (r *RefreshTokenRequest) GetScopes() []string                       { return r.Scopes }
func (r *RefreshTokenRequest) GetSubject() string                        { return r.UserID }
func (r *RefreshTokenRequest) SetCurrentScopes(scopes []string)          { r.Scopes = scopes }
func (r *RefreshTokenRequest) GetCodeChallenge() *protocol.CodeChallenge { return nil }
func (r *RefreshTokenRequest) GetNonce() string                          { return "" }
func (r *RefreshTokenRequest) GetID() string                             { return r.RefreshToken.ID }
func (r *RefreshTokenRequest) GetSessionID() string                      { return r.SessionID }

var _ storm.RefreshTokenRequest = (*RefreshTokenRequest)(nil)
