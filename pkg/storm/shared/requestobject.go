package shared

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
)

// RequestObjectClientLookup is a function that looks up a client by ID
// for request object verification. The returned client must implement
// JWKSProvider (and optionally JWKSURIProvider) to provide verification keys.
type RequestObjectClientLookup func(ctx context.Context, clientID string) (Client, error)

// ParseAndValidateRequestObject parses and validates a JWT request object
// (OIDC Core §6.1, RFC 9101). It:
//  1. Parses the JWT without verification to extract claims
//  2. Validates iss == client_id and aud contains the issuer
//  3. Looks up the client and verifies the JWT signature
//  4. Validates time claims (exp, nbf)
//  5. Copies request object claims into the auth request
//
// skipTLSVerify controls whether TLS certificate verification is skipped when
// fetching the client's JWKS from jwks_uri (testing only).
// allowPrivateIPs controls whether SSRF validation is skipped for private IPs.
//
// Returns protocol.ErrInvalidRequestObject on any validation failure.
func ParseAndValidateRequestObject(ctx context.Context, authReq *protocol.AuthRequest, lookupClient RequestObjectClientLookup, skipTLSVerify, allowPrivateIPs bool) error {
	requestObject := new(protocol.RequestObject)
	payload, err := protocol.ParseToken(authReq.RequestParam, requestObject)
	if err != nil {
		return protocol.ErrInvalidRequestObject().WithDescription("invalid request object").WithParent(err)
	}

	slog.Info("ParseAndValidateRequestObject: after ParseToken",
		slog.String("payload", string(payload)),
		slog.String("ro_scopes", fmt.Sprintf("%v", requestObject.Scopes)),
		slog.String("ro_redirect_uri", requestObject.RedirectURI),
		slog.String("ro_response_type", string(requestObject.ResponseType)),
		slog.String("ro_client_id", requestObject.ClientID),
		slog.String("ro_issuer", requestObject.Issuer),
		slog.Any("ro_audience", requestObject.Audience),
	)

	// Validate request object claims
	if requestObject.Issuer == "" {
		return protocol.ErrInvalidRequestObject().WithDescription("request object missing iss claim")
	}
	if requestObject.Issuer != requestObject.ClientID {
		return protocol.ErrInvalidRequestObject().WithDescription("missing or wrong issuer in request object")
	}
	issuer := IssuerFromContext(ctx)
	if !slices.Contains(requestObject.Audience, issuer) {
		return protocol.ErrInvalidRequestObject().WithDescription("issuer missing in request object audience")
	}

	// Look up the client and verify signature using client's JWKS
	client, err := lookupClient(ctx, requestObject.Issuer)
	if err != nil {
		return protocol.ErrInvalidRequestObject().WithDescription("client not found for request object issuer")
	}
	if requestObject.ClientID != "" && requestObject.ClientID != authReq.ClientID && authReq.ClientID != "" {
		return protocol.ErrInvalidRequestObject().WithDescription("missing or wrong client id in request object")
	}
	if requestObject.ResponseType != "" && requestObject.ResponseType != authReq.ResponseType && authReq.ResponseType != "" {
		return protocol.ErrInvalidRequestObject().WithDescription("missing or wrong response type in request object")
	}

	// Get client's JWKS for signature verification
	clientKS, ok := client.(JWKSProvider)
	if !ok {
		return protocol.ErrInvalidRequestObject().WithDescription("client does not support request object verification")
	}

	var clientKeys []jwk.Key
	if uriProvider, ok := client.(JWKSURIProvider); ok && uriProvider.ClientJWKSURI() != "" {
		fetchedKeys, err := FetchJWKSFromURI(uriProvider.ClientJWKSURI(), skipTLSVerify, allowPrivateIPs)
		if err != nil {
			clientKeys = clientKS.ClientJWKS()
		} else {
			clientKeys = fetchedKeys
		}
	} else {
		clientKeys = clientKS.ClientJWKS()
	}

	if len(clientKeys) == 0 {
		return protocol.ErrInvalidRequestObject().WithDescription("client has no registered keys")
	}

	// Verify signature using client's keys
	if err := verifyRequestObjectSignature(ctx, authReq.RequestParam, payload, clientKeys); err != nil {
		return protocol.ErrInvalidRequestObject().WithDescription("invalid request object signature").WithParent(err)
	}

	// Determine whether the client is configured for FAPI requirements.
	isFAPI := false
	if fc, ok := client.(FAPIProfileClient); ok {
		isFAPI = fc.FAPIProfile()
	}

	// Validate time claims (OIDC Core: exp/nbf are OPTIONAL; FAPI 2.0 §5.3.2.2 requires both).
	now := time.Now()
	const clockSkew = 10 * time.Second

	if isFAPI {
		// FAPI 2.0 §5.3.2.2: The request object MUST contain an exp claim.
		if requestObject.ExpiresAt == 0 {
			return protocol.ErrInvalidRequestObject().WithDescription("request object is missing required 'exp' claim")
		}
		if now.After(time.Unix(requestObject.ExpiresAt, 0).Add(clockSkew)) {
			return protocol.ErrInvalidRequestObject().WithDescription("request object has expired")
		}

		// FAPI 2.0 §5.3.2.2: The request object MUST contain a nbf claim.
		if requestObject.NotBefore == 0 {
			return protocol.ErrInvalidRequestObject().WithDescription("request object is missing required 'nbf' claim")
		}
		if now.Before(time.Unix(requestObject.NotBefore, 0).Add(-clockSkew)) {
			return protocol.ErrInvalidRequestObject().WithDescription("request object is not yet valid (nbf)")
		}

		// FAPI 1.0/2.0: The request object lifetime (exp - nbf) MUST NOT exceed 60 minutes.
		const maxRequestObjectLifetime = 60 * time.Minute
		if time.Unix(requestObject.ExpiresAt, 0).Sub(time.Unix(requestObject.NotBefore, 0)) > maxRequestObjectLifetime {
			return protocol.ErrInvalidRequestObject().WithDescription("request object lifetime exceeds 60 minutes")
		}
	} else {
		// OIDC Core: exp/nbf are not required, but if present, still validate them.
		if requestObject.ExpiresAt != 0 && now.After(time.Unix(requestObject.ExpiresAt, 0).Add(clockSkew)) {
			return protocol.ErrInvalidRequestObject().WithDescription("request object has expired")
		}
		if requestObject.NotBefore != 0 && now.Before(time.Unix(requestObject.NotBefore, 0).Add(-clockSkew)) {
			return protocol.ErrInvalidRequestObject().WithDescription("request object is not yet valid (nbf)")
		}
	}

	// OIDC Core §6.1: When both query-string and request object provide a
	// nonce, they MUST match. Mismatched nonces make the request ambiguous.
	if requestObject.Nonce != "" && authReq.Nonce != "" && requestObject.Nonce != authReq.Nonce {
		return protocol.ErrInvalidRequest().WithDescription("nonce in query does not match nonce in request object")
	}

	// Copy request object values into the auth request.
	CopyRequestObjectToAuthRequest(authReq, requestObject)
	return nil
}

// CopyRequestObjectToAuthRequest copies request object claims into the
// authorization request, overriding any existing values.
//
// FAPI 2.0 §5.3.1: when a request object is present, the authorization server
// SHALL NOT use any parameter values from the query string and SHALL only use
// parameter values from the request object. Most fields are therefore
// unconditionally assigned from the request object — any query-string-only
// values (e.g. state) that are absent from the request object are cleared.
// RequestURI is preserved when the request object does not carry one, because
// it is needed downstream as a sentinel (e.g. to skip the
// signed-request-object-required check for request_uri-based JAR).
//
// Per OIDC Core §6.1 and RFC 9101, the request object is a transport envelope
// for authorization request parameters. Once the signature is verified and the
// claims are copied, the original RequestParam (the raw JWT string) has no
// further use — no downstream flow reads it. Clearing it avoids accidentally
// re-processing the same JWT and keeps the AuthRequest semantically clean.
func CopyRequestObjectToAuthRequest(authReq *protocol.AuthRequest, requestObject *protocol.RequestObject) {
	authReq.ResponseType = requestObject.ResponseType
	authReq.ClientID = requestObject.ClientID
	authReq.Scopes = requestObject.Scopes
	authReq.RedirectURI = requestObject.RedirectURI
	authReq.State = requestObject.State
	authReq.ResponseMode = requestObject.ResponseMode
	authReq.Nonce = requestObject.Nonce
	authReq.Display = requestObject.Display
	authReq.Prompt = requestObject.Prompt
	authReq.MaxAge = requestObject.MaxAge
	authReq.UILocales = requestObject.UILocales
	authReq.IDTokenHint = requestObject.IDTokenHint
	authReq.LoginHint = requestObject.LoginHint
	authReq.ACRValues = requestObject.ACRValues
	authReq.CodeChallenge = requestObject.CodeChallenge
	authReq.CodeChallengeMethod = requestObject.CodeChallengeMethod
	// Only overwrite DPoPJKT if the request object actually contains it;
	// otherwise preserve any value captured from the PAR DPoP proof header.
	if requestObject.DPoPJKT != "" {
		authReq.DPoPJKT = requestObject.DPoPJKT
	}
	authReq.Claims = requestObject.Claims
	authReq.Resource = requestObject.Resource
	authReq.AuthorizationDetails = requestObject.AuthorizationDetails
	// Preserve the original request_uri when the request object does not
	// carry one. For request_uri-based JAR, the original URI is the source
	// of the request object and must remain available as a sentinel (e.g.
	// to skip the signed-request-object-required check). For PAR, the PAR
	// urn was already set before parsing.
	if requestObject.RequestURI != "" {
		authReq.RequestURI = requestObject.RequestURI
	}
	// Clear the raw request JWT — its signature has been verified and its
	// claims copied above; no downstream consumer reads RequestParam after
	// this point (OIDC Core §6.1, RFC 9101).
	authReq.RequestParam = ""
}

// verifyRequestObjectSignature verifies a JWT signature using the client's JWKS keys.
func verifyRequestObjectSignature(ctx context.Context, token string, payload []byte, keys []jwk.Key) error {
	parsed, err := jws.Parse([]byte(token))
	if err != nil {
		return fmt.Errorf("error parsing token: %w", err)
	}
	keyID, alg := protocol.GetKeyIDAndAlg(parsed)
	matchingKey, err := protocol.FindMatchingKey(keyID, protocol.KeyUseSignature, alg, keys...)
	if err != nil {
		return fmt.Errorf("no matching key found: %w", err)
	}
	_, err = protocol.VerifySignature(ctx, parsed, []byte(token), matchingKey, alg)
	return err
}
