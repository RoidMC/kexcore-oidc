package token

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// --- parsing ---

func parseAccessTokenRequest(form map[string][]string, decoder *protocol.Decoder) (*protocol.AccessTokenRequest, error) {
	req := new(protocol.AccessTokenRequest)
	if err := decoder.Decode(req, form); err != nil {
		return nil, err
	}
	return req, nil
}

func parseRefreshTokenRequest(form map[string][]string, decoder *protocol.Decoder) (*protocol.RefreshTokenRequest, error) {
	req := new(protocol.RefreshTokenRequest)
	if err := decoder.Decode(req, form); err != nil {
		return nil, err
	}
	return req, nil
}

func parseClientCredentialsRequest(form map[string][]string, decoder *protocol.Decoder) (*protocol.ClientCredentialsRequest, error) {
	req := new(protocol.ClientCredentialsRequest)
	if err := decoder.Decode(req, form); err != nil {
		return nil, err
	}
	return req, nil
}

// --- validation ---

func validateGrantType(client storm.Client, grantType protocol.GrantType) bool {
	type grantTypesProvider interface {
		GrantTypes() []protocol.GrantType
	}
	if gp, ok := client.(grantTypesProvider); ok {
		return slices.Contains(gp.GrantTypes(), grantType)
	}
	// If the client doesn't declare grant types, allow common ones
	return grantType == protocol.GrantTypeCode || grantType == protocol.GrantTypeRefreshToken
}

// verifyPKCE validates the PKCE code_verifier against the stored code_challenge
// per RFC 7636 §4.6. If the auth request has no code_challenge, PKCE is not required.
func verifyPKCE(authReq storm.AuthRequest, codeVerifier string) error {
	cc := authReq.GetCodeChallenge()
	if cc == nil || cc.Challenge == "" {
		return nil
	}
	if codeVerifier == "" {
		return protocol.ErrInvalidGrant().WithDescription("code_verifier required (PKCE)")
	}
	switch cc.Method {
	case protocol.CodeChallengeMethodS256:
		h := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		if computed != cc.Challenge {
			return protocol.ErrInvalidGrant().WithDescription("PKCE verification failed")
		}
	case protocol.CodeChallengeMethodPlain:
		if codeVerifier != cc.Challenge {
			return protocol.ErrInvalidGrant().WithDescription("PKCE verification failed")
		}
	default:
		return protocol.ErrInvalidGrant().WithDescription("unsupported code_challenge_method: %s", cc.Method)
	}
	return nil
}

func validateRefreshScopes(requestedScopes []string, refreshReq storm.RefreshTokenRequest) error {
	if len(requestedScopes) == 0 {
		return nil
	}
	for _, scope := range requestedScopes {
		if !slices.Contains(refreshReq.GetScopes(), scope) {
			return protocol.ErrInvalidScope()
		}
	}
	refreshReq.SetCurrentScopes(requestedScopes)
	return nil
}
