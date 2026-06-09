package token

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
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

// --- error handling ---

// tokenError writes a token error response.
// Per RFC 6749 §5.2, token errors use HTTP 400 with JSON body.
func tokenError(w http.ResponseWriter, r *http.Request, err error) {
	shared.WriteError(w, r, err, nil)
}

// --- ID token helpers ---

// getNonce extracts the nonce from a TokenRequest if it implements NonceProvider.
func getNonce(req storm.TokenRequest) string {
	type nonceProvider interface {
		GetNonce() string
	}
	if np, ok := req.(nonceProvider); ok {
		return np.GetNonce()
	}
	return ""
}

// hashToken computes the at_hash/c_hash claim value for the given token
// using the hash algorithm appropriate for the signing algorithm.
func hashToken(accessToken string, sigAlg string) string {
	h, err := crypto.GetHashAlgorithm(sigAlg)
	if err != nil {
		return ""
	}
	return crypto.HashString(h, accessToken, true)
}

// --- ID token encryption ---

func encryptIDToken(signedToken string, client storm.Client, cr storm.UniCrypto, alg, enc string) (string, error) {
	switch alg {
	case protocol.JWEAlgDir:
		kp, ok := cr.(tokenEncryptionKeyProvider)
		if !ok || kp.TokenEncryptionKey() == nil {
			return "", fmt.Errorf("dir encryption requested but Crypto does not implement TokenEncryptionKeyProvider")
		}
		return protocol.EncryptTokenJWE(signedToken, kp.TokenEncryptionKey(), alg, enc)
	case protocol.JWEAlgSM23:
		pk, ok := cr.(sm2EncryptionKeyProvider)
		if !ok || pk.SM2TokenEncryptionPublicKey() == nil {
			return "", fmt.Errorf("SM2 encryption requested but Crypto does not implement SM2TokenEncryptionPublicKeyProvider")
		}
		return protocol.EncryptTokenJWE(signedToken, pk.SM2TokenEncryptionPublicKey(), alg, enc)
	case protocol.JWEAlgSM93:
		pk, ok := cr.(sm9EncryptionKeyProvider)
		if !ok || pk.SM9TokenEncryptionKey() == nil {
			return "", fmt.Errorf("SM9 encryption requested but Crypto does not implement SM9TokenEncryptionKeyProvider")
		}
		return protocol.EncryptTokenSM9(signedToken, pk.SM9TokenEncryptionKey())
	case protocol.JWEAlgRSAOAEP, protocol.JWEAlgRSAOAEP256, protocol.JWEAlgRSAOAEP384, protocol.JWEAlgRSAOAEP512,
		protocol.JWEAlgECDHES, protocol.JWEAlgECDHESA128KW, protocol.JWEAlgECDHESA192KW, protocol.JWEAlgECDHESA256KW,
		protocol.JWEAlgA128KW, protocol.JWEAlgA192KW, protocol.JWEAlgA256KW,
		protocol.JWEAlgA128GCMKW, protocol.JWEAlgA192GCMKW, protocol.JWEAlgA256GCMKW:
		if ckp, ok := client.(storm.ClientKeyProvider); ok {
			key := ckp.ClientEncryptionKey()
			if key == nil {
				return "", fmt.Errorf("%s encryption requested but client has no encryption key", alg)
			}
			return protocol.EncryptTokenJWE(signedToken, key, alg, enc)
		}
		return "", fmt.Errorf("%s encryption requested but client does not implement ClientKeyProvider", alg)
	default:
		return "", fmt.Errorf("unsupported JWE key management algorithm: %s", alg)
	}
}

// --- pairwise subject ---

// pairwiseTokenRequest wraps a TokenRequest with a pairwise-transformed subject.
type pairwiseTokenRequest struct {
	inner   storm.TokenRequest
	subject string
}

func (r *pairwiseTokenRequest) GetSubject() string    { return r.subject }
func (r *pairwiseTokenRequest) GetClientID() string   { return r.inner.GetClientID() }
func (r *pairwiseTokenRequest) GetScopes() []string   { return r.inner.GetScopes() }
func (r *pairwiseTokenRequest) GetAudience() []string { return r.inner.GetAudience() }

// applyPairwise transforms the subject if the client requires pairwise identifiers.
// Returns the original request unchanged if pairwise is not applicable.
func (p *Plugin) applyPairwise(req storm.TokenRequest, client storm.Client) storm.TokenRequest {
	if p.pairwiseTransformer == nil {
		return req
	}
	clientID := client.GetID()
	if !p.pairwiseTransformer.IsPairwiseClient(clientID) {
		return req
	}
	return &pairwiseTokenRequest{
		inner:   req,
		subject: p.pairwiseTransformer.Transform(clientID, req.GetSubject()),
	}
}
