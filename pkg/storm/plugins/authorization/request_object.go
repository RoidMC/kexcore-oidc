package authorization

// Request Object / request_uri / PAR resolution (OIDC Core §6.1, RFC 9101).

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/shared"
)

// applyRequestObject parses and validates a JWT request object (OIDC Core §6.1).
func (p *Plugin) applyRequestObject(ctx context.Context, authReq *protocol.AuthRequest) error {
	lookupClient := func(ctx context.Context, clientID string) (shared.Client, error) {
		return p.clientStore.GetClientByClientID(ctx, clientID)
	}
	return shared.ParseAndValidateRequestObject(ctx, authReq, lookupClient, p.skipTLSCertVerify, p.allowPrivateIPs)
}

// applyRequestURI fetches and validates a signed JWT request object from a URL (OIDC Core §6.1).
func (p *Plugin) applyRequestURI(ctx context.Context, authReq *protocol.AuthRequest) error {
	// Fetch the JWT from the URL, with SSRF protections: pre-flight URL
	// validation plus dial-time IP checks (see shared.FetchRemoteURL).
	resp, err := shared.FetchRemoteURL(authReq.RequestURI, p.skipTLSCertVerify, p.allowPrivateIPs)
	if err != nil {
		return protocol.ErrInvalidRequestObject().WithDescription("failed to fetch request_uri: %s", authReq.RequestURI).WithParent(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.ErrInvalidRequestObject().WithDescription("request_uri returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return protocol.ErrInvalidRequestObject().WithDescription("failed to read request_uri response").WithParent(err)
	}

	// Set the fetched JWT as the request parameter and validate using shared logic.
	authReq.RequestParam = strings.TrimSpace(string(body))
	lookupClient := func(ctx context.Context, clientID string) (shared.Client, error) {
		return p.clientStore.GetClientByClientID(ctx, clientID)
	}
	return shared.ParseAndValidateRequestObject(ctx, authReq, lookupClient, p.skipTLSCertVerify, p.allowPrivateIPs)
}

// applyPARRequest resolves a Pushed Authorization Request (RFC 9101 §5.2).
func (p *Plugin) applyPARRequest(ctx context.Context, authReq *protocol.AuthRequest) error {
	parReq, err := p.parStore.GetPushedAuthRequest(ctx, authReq.RequestURI)
	if err != nil {
		return protocol.ErrInvalidRequest().WithDescription("invalid request_uri").WithParent(err)
	}

	// DEBUG: trace PAR data before merging
	slog.Info("applyPARRequest: PAR data retrieved",
		slog.Any("par_scopes", parReq.Scopes),
		slog.String("par_client_id", parReq.ClientID),
		slog.String("par_redirect_uri", parReq.RedirectURI),
		slog.Any("incoming_scopes", authReq.Scopes),
		slog.String("incoming_client_id", authReq.ClientID),
	)

	// RFC 9126: The request_uri is bound to the client that created it.
	// If the authorize endpoint carries a different client_id, reject.
	if authReq.ClientID != "" && authReq.ClientID != parReq.ClientID {
		return protocol.ErrInvalidRequest().WithDescription("client_id does not match the pushed authorization request")
	}

	// FAPI 2.0 / RFC 9126: when PAR is used, authorization parameters MUST
	// come exclusively from the pushed request. The authorize endpoint query
	// string only carries request_uri (and optionally client_id for
	// identification). All other parameters from the query string are ignored.
	// We unconditionally assign from the PAR data so that any stale
	// query-string values (e.g. state) that were not part of the pushed
	// request are cleared.
	authReq.ClientID = parReq.ClientID
	authReq.RedirectURI = parReq.RedirectURI
	authReq.Scopes = parReq.Scopes
	authReq.State = parReq.State
	authReq.ResponseType = parReq.ResponseType
	authReq.ResponseMode = parReq.ResponseMode
	if parReq.Nonce != "" && authReq.Nonce != "" && authReq.Nonce != parReq.Nonce {
		return protocol.ErrInvalidRequest().WithDescription("nonce in query does not match nonce in PAR request")
	}
	authReq.Nonce = parReq.Nonce
	authReq.Display = parReq.Display
	authReq.Prompt = parReq.Prompt
	authReq.MaxAge = parReq.MaxAge
	authReq.UILocales = parReq.UILocales
	authReq.IDTokenHint = parReq.IDTokenHint
	authReq.LoginHint = parReq.LoginHint
	authReq.ACRValues = parReq.ACRValues
	authReq.CodeChallenge = parReq.CodeChallenge
	authReq.CodeChallengeMethod = parReq.CodeChallengeMethod
	authReq.DPoPJKT = parReq.DPoPJKT
	authReq.Claims = parReq.Claims
	authReq.Resource = parReq.Resource
	authReq.AuthorizationDetails = parReq.AuthorizationDetails
	authReq.RequestParam = parReq.RequestParam

	// If the pushed request included a request object, parse and validate it.
	if authReq.RequestParam != "" {
		if err := p.applyRequestObject(ctx, authReq); err != nil {
			return err
		}
	}

	return nil
}

// validateIDTokenHint validates an id_token_hint (OIDC Core §3.1.2.2).
// It uses protocol.VerifyIDTokenHint to verify the token and extract claims.
// Returns the subject and client ID (from aud) for caller-side subject matching.
// Per OIDC Core §3.1.2.2: "If the End-User identified by the ID Token
// is logged in or is logged in by the request, then the Authorization Server
// returns a positive response; otherwise, it SHOULD return an error."
func (p *Plugin) validateIDTokenHint(ctx context.Context, idTokenHint string) (subject, clientID string, err error) {
	if p.keyStore == nil {
		return "", "", nil
	}

	verifier := protocol.NewIDTokenHintVerifier(
		shared.IssuerFromContext(ctx),
		nil,
	)
	verifier.KeyStore = p.keyStore

	claims, err := protocol.VerifyIDTokenHint(ctx, idTokenHint, verifier)
	if err != nil {
		// Expired ID token hints are acceptable per OIDC spec.
		var expiredErr protocol.IDTokenHintExpiredError
		if errors.As(err, &expiredErr) && claims != nil {
			// Token is expired but claims are still valid for hint purposes.
		} else {
			return "", "", err
		}
	}

	subject = claims.Subject
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	return subject, clientID, nil
}
