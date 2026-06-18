// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package storage

import (
	"log/slog"
	"slices"
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
	Resources     []string // RFC 8707: Resource Indicators

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

// GetResources implements storm.ResourceIndicator (RFC 8707).
// Returns the resource indicator values from the authorization request.
func (a *AuthRequest) GetResources() []string { return a.Resources }

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
		Resources:          authReq.Resource,
		extraIDTokenClaims: buildIDTokenClaims(authReq.Scopes, authReq.Claims, user, authReq.ResponseType),
		sessionID:          uuid.NewString(),
	}
}

// buildIDTokenClaims returns extra claims to merge into the ID token
// based on the granted scopes (OIDC Core §5.4) and the claims.id_token
// request parameter (OIDC Core §5.5).
//
// OIDC Core §5.4: For Authorization Endpoint responses (implicit/hybrid flows),
// scope-based standard claims are included in the ID token. For Token Endpoint
// responses (authorization_code flow), only claims explicitly requested via the
// claims.id_token parameter are included.
func buildIDTokenClaims(scopes []string, cr *protocol.ClaimsRequest, user *User, responseType protocol.ResponseType) map[string]any {
	if user == nil {
		return nil
	}
	claims := make(map[string]any)

	// OIDC Core §5.4: The Claims requested by the profile, email, address,
	// and phone scope values are returned from the UserInfo Endpoint, except
	// for response_type=id_token where they are returned in the ID token
	// (no access token is issued, so UserInfo cannot be called).
	if responseType == protocol.ResponseTypeIDTokenOnly {
		if slices.Contains(scopes, protocol.ScopeProfile) {
			claims["name"] = user.FirstName + " " + user.LastName
			claims["given_name"] = user.FirstName
			claims["family_name"] = user.LastName
			claims["middle_name"] = "N/A"
			claims["nickname"] = user.Username
			claims["preferred_username"] = user.Username
			claims["profile"] = "https://example.com"
			claims["picture"] = "https://example.com/avatar.png"
			claims["website"] = "https://example.com"
			claims["gender"] = "other"
			claims["birthdate"] = "2000-01-01"
			claims["zoneinfo"] = "UTC"
			claims["locale"] = user.PreferredLanguage
			claims["updated_at"] = user.UpdatedAt
		}
		if slices.Contains(scopes, protocol.ScopeEmail) {
			claims["email"] = user.Email
			claims["email_verified"] = user.EmailVerified
		}
		if slices.Contains(scopes, protocol.ScopePhone) {
			claims["phone_number"] = user.Phone
			claims["phone_number_verified"] = user.PhoneVerified
		}
		if slices.Contains(scopes, protocol.ScopeAddress) {
			claims["address"] = map[string]string{"formatted": "N/A"}
		}
	}

	// OIDC Core §5.5: claims.id_token applies to ALL flows.
	if cr != nil && cr.IDToken != nil {
		for name, req := range cr.IDToken {
			switch name {
			case "auth_time", "acr", "amr", "azp":
				// Handled directly by the token plugin; skip.
			case "name":
				setClaimValue(claims, "name", req, user.FirstName+" "+user.LastName)
			case "given_name":
				setClaimValue(claims, "given_name", req, user.FirstName)
			case "family_name":
				setClaimValue(claims, "family_name", req, user.LastName)
			case "middle_name":
				setClaimValue(claims, "middle_name", req, "N/A")
			case "nickname":
				setClaimValue(claims, "nickname", req, user.Username)
			case "preferred_username":
				setClaimValue(claims, "preferred_username", req, user.Username)
			case "profile":
				setClaimValue(claims, "profile", req, "https://example.com")
			case "picture":
				setClaimValue(claims, "picture", req, "https://example.com/avatar.png")
			case "website":
				setClaimValue(claims, "website", req, "https://example.com")
			case "email":
				setClaimValue(claims, "email", req, user.Email)
				claims["email_verified"] = user.EmailVerified
			case "email_verified":
				claims["email_verified"] = user.EmailVerified
			case "gender":
				setClaimValue(claims, "gender", req, "other")
			case "birthdate":
				setClaimValue(claims, "birthdate", req, "2000-01-01")
			case "zoneinfo":
				setClaimValue(claims, "zoneinfo", req, "UTC")
			case "locale":
				setClaimValue(claims, "locale", req, user.PreferredLanguage)
			case "phone_number":
				setClaimValue(claims, "phone_number", req, user.Phone)
				claims["phone_number_verified"] = user.PhoneVerified
			case "phone_number_verified":
				claims["phone_number_verified"] = user.PhoneVerified
			case "address":
				setClaimValue(claims, "address", req, map[string]string{"formatted": "N/A"})
			case "updated_at":
				setClaimValue(claims, "updated_at", req, user.UpdatedAt)
			}
		}
	}

	if len(claims) == 0 {
		return nil
	}
	return claims
}

func setClaimValue(claims map[string]any, key string, req *protocol.ClaimRequest, defaultValue any) {
	if req != nil && req.Value != nil {
		claims[key] = req.Value
	} else {
		claims[key] = defaultValue
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
func (r *RefreshTokenRequest) GetDPoPJKT() string                        { return r.DPoPJKT }

var _ storm.RefreshTokenRequest = (*RefreshTokenRequest)(nil)
