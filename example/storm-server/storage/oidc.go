// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package storage

import (
	"log/slog"
	"time"

	"golang.org/x/text/language"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

const (
	CustomScope                 = "custom_scope"
	CustomClaim                 = "custom_claim"
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
	ResponseType  oidc.ResponseType
	ResponseMode  oidc.ResponseMode
	Nonce         string
	CodeChallenge *OIDCCodeChallenge

	done      bool
	authTime  time.Time
	sessionID string
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

func (a *AuthRequest) GetID() string                          { return a.ID }
func (a *AuthRequest) GetACR() string                         { return "" }
func (a *AuthRequest) GetAMR() []string                       { if a.done { return []string{"pwd"} }; return nil }
func (a *AuthRequest) GetAudience() []string                  { return []string{a.ApplicationID} }
func (a *AuthRequest) GetAuthTime() time.Time                 { return a.authTime }
func (a *AuthRequest) GetClientID() string                    { return a.ApplicationID }
func (a *AuthRequest) GetCodeChallenge() *protocol.CodeChallenge  { return CodeChallengeToOIDC(a.CodeChallenge) }
func (a *AuthRequest) GetNonce() string                       { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string                 { return a.CallbackURI }
func (a *AuthRequest) GetResponseType() oidc.ResponseType     { return a.ResponseType }
func (a *AuthRequest) GetResponseMode() oidc.ResponseMode     { return a.ResponseMode }
func (a *AuthRequest) GetScopes() []string                    { return a.Scopes }
func (a *AuthRequest) GetState() string                       { return a.TransferState }
func (a *AuthRequest) GetSubject() string                     { return a.UserID }
func (a *AuthRequest) Done() bool                             { return a.done }
func (a *AuthRequest) GetSessionID() string                   { return a.sessionID }

func PromptToInternal(oidcPrompt oidc.SpaceDelimitedArray) []string {
	prompts := make([]string, 0, len(oidcPrompt))
	for _, p := range oidcPrompt {
		switch p {
		case oidc.PromptNone, oidc.PromptLogin, oidc.PromptConsent, oidc.PromptSelectAccount:
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

func authRequestToInternal(authReq *oidc.AuthRequest, userID string) *AuthRequest {
	var codeChallenge *OIDCCodeChallenge
	if authReq.CodeChallenge != "" {
		codeChallenge = &OIDCCodeChallenge{
			Challenge: authReq.CodeChallenge,
			Method:    string(authReq.CodeChallengeMethod),
		}
	}
	return &AuthRequest{
		CreationDate:  time.Now(),
		ApplicationID: authReq.ClientID,
		CallbackURI:   authReq.RedirectURI,
		TransferState: authReq.State,
		Prompt:        PromptToInternal(authReq.Prompt),
		UiLocales:     authReq.UILocales,
		LoginHint:     authReq.LoginHint,
		MaxAuthAge:    MaxAgeToInternal(authReq.MaxAge),
		UserID:        userID,
		Scopes:        authReq.Scopes,
		ResponseType:  authReq.ResponseType,
		ResponseMode:  authReq.ResponseMode,
		Nonce:         authReq.Nonce,
		CodeChallenge: codeChallenge,
	}
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

func (r *RefreshTokenRequest) GetAMR() []string                 { return r.AMR }
func (r *RefreshTokenRequest) GetAudience() []string            { return r.Audience }
func (r *RefreshTokenRequest) GetAuthTime() time.Time           { return r.AuthTime }
func (r *RefreshTokenRequest) GetClientID() string              { return r.ApplicationID }
func (r *RefreshTokenRequest) GetScopes() []string               { return r.Scopes }
func (r *RefreshTokenRequest) GetSubject() string                { return r.UserID }
func (r *RefreshTokenRequest) SetCurrentScopes(scopes []string)  { r.Scopes = scopes }
func (r *RefreshTokenRequest) GetCodeChallenge() *protocol.CodeChallenge { return nil }
func (r *RefreshTokenRequest) GetNonce() string                  { return "" }
func (r *RefreshTokenRequest) GetID() string                     { return r.RefreshToken.ID }
func (r *RefreshTokenRequest) GetSessionID() string              { return r.SessionID }

var _ storm.RefreshTokenRequest = (*RefreshTokenRequest)(nil)