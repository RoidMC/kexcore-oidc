package endsession

import (
	"context"
	"errors"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

func parseEndSessionRequest(form map[string][]string, decoder *protocol.Decoder) (*protocol.EndSessionRequest, error) {
	req := new(protocol.EndSessionRequest)
	if err := decoder.Decode(req, form); err != nil {
		return nil, err
	}
	return req, nil
}

func validateEndSessionRequest(ctx context.Context, req *protocol.EndSessionRequest, p *Plugin) (*storm.EndSessionRequest, error) {
	session := &storm.EndSessionRequest{}

	// Validate id_token_hint per OIDC Session Management §5.
	// If present, extract the subject and validate client binding.
	// Expired tokens are treated as non-fatal - the claims can still
	// be trusted for logout purposes if signature validation passes.
	if req.IdTokenHint != "" {
		if p.keyStore == nil {
			return nil, protocol.ErrInvalidRequest().WithDescription("id_token_hint provided but IdTokenHintVerifier not configured")
		}

		v := &protocol.IDTokenHintVerifier{
			Issuer:    shared.IssuerFromContext(ctx),
			KeyStore:  p.keyStore,
			Offset:    p.offset,
			MaxAgeIAT: p.maxAgeIAT,
			MaxAge:    p.maxAge,
		}
		claims, err := protocol.VerifyIDTokenHint(ctx, req.IdTokenHint, v)
		if err != nil {
			var expired *protocol.IDTokenHintExpiredError
			if !errors.As(err, &expired) {
				return nil, protocol.ErrInvalidRequest().WithDescription("invalid id_token_hint").WithParent(err)
			}
		}

		if claims != nil {
			session.UserID = claims.Subject
			// Extract client_id from aud (OIDC Core: aud contains the client_id).
			if claims.ClientID != "" {
				session.ClientID = claims.ClientID
			} else if aud := claims.GetAudience(); len(aud) > 0 {
				session.ClientID = aud[0]
			}
			session.IDTokenHintClaims = claims
		}
	}

	// Validate requested client_id binding.
	if req.ClientID != "" {
		if session.ClientID != "" && req.ClientID != session.ClientID {
			return nil, protocol.ErrInvalidRequest().WithDescription("client_id does not match id_token_hint aud")
		}
		session.ClientID = req.ClientID
	}

	// Validate post_logout_redirect_uri against client configuration.
	// Per OIDC RP-Initiated Logout 1.0 §2: if the URI is not registered,
	// the OP MUST NOT redirect to it, but should still perform the logout.
	if req.PostLogoutRedirectURI != "" && session.ClientID != "" {
		if p.clientStore != nil {
			client, err := p.clientStore.GetClientByClientID(ctx, session.ClientID)
			if err == nil {
				redirectURI := validatePostLogoutRedirectURI(client, req.PostLogoutRedirectURI)
				if redirectURI != "" {
					session.RedirectURI = redirectURI
				} else {
					session.InvalidRedirectURI = true
				}
			}
		}
	}

	session.State = req.State

	return session, nil
}

// validatePostLogoutRedirectURI checks if the given URI is valid for the client.
// Per OIDC RP-Initiated Logout 1.0 §2: the OP MUST verify the post_logout_redirect_uri
// has been registered by the RP. If not registered, the OP MUST NOT redirect to it.
// Returns the validated URI or empty string if validation fails.
func validatePostLogoutRedirectURI(client storm.Client, uri string) string {
	if p, ok := client.(storm.PostLogoutRedirectURIClient); ok {
		for _, u := range p.PostLogoutRedirectURIs() {
			if u == uri {
				return uri
			}
		}
	}
	return ""
}
