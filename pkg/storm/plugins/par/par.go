// Package par implements the OAuth 2.0 Pushed Authorization Requests plugin.
//
// It handles POST /par (RFC 9126 §3), allowing clients to push
// authorization request parameters to the server and receive a
// request_uri in return.
package par

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// NewWithConfig creates a new PAR plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	if cfg.Lifetime == 0 {
		// RFC 9126: lifetime should be relatively short (e.g., between 5 and 600 seconds).
		// FAPI 2.0 Security Profile §5.3.2.2-12: expires_in MUST be < 600 seconds.
		// 90s keeps tests fast while leaving enough time for request_uri reuse flows.
		cfg.Lifetime = 90 * time.Second
	}
	return &Plugin{
		store:             cfg.Store,
		clientStore:       cfg.ClientStore,
		decoder:           cfg.Decoder,
		lifetime:          cfg.Lifetime,
		requireDPoP:       cfg.RequireDPoP,
		requireMtls:       cfg.RequireMtls,
		skipTLSCertVerify: cfg.SkipTLSCertVerify,
		allowPrivateIPs:   cfg.AllowPrivateIPs,
	}
}

// init self-registers the PAR plugin in the global registry.
func init() {
	storm.RegisterPlugin("par", storm.PriorityPAR, func(ctx *storm.PluginContext) storm.Plugin {
		parStore, ok := ctx.Storage.(storm.PARStore)
		if !ok {
			return nil
		}
		return NewWithConfig(Config{
			Store:             parStore,
			ClientStore:       ctx.Storage.(storm.ClientStore),
			Decoder:           ctx.Decoder,
			Lifetime:          ctx.PARLifetime,
			RequireDPoP:       ctx.RequireDPoP,
			RequireMtls:       ctx.RequireMtls,
			SkipTLSCertVerify: ctx.SkipTLSCertVerify,
			AllowPrivateIPs:   ctx.AllowPrivateIPs,
		})
	})
}

// Category returns CategoryStandard — PAR is optional.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string {
	return []string{"PARStore", "ClientStore"}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "par" }

// OAuth 2.0 standard endpoint: POST /par (RFC 9126 §3)
// Register installs the POST /par route.
func (p *Plugin) Register(r chi.Router) {
	r.Post("/par", p.handle)
}

// Contribute returns the discovery fields for the PAR endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.PushedAuthorizationRequestEndpoint = shared.EndpointURL(ctx, protocol.NewEndpoint("/par"))
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	// DEBUG: log every request hitting the PAR endpoint
	slog.Info("PAR handle: REQUEST RECEIVED",
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	// Authenticate the client.
	client, err := p.authenticateClient(r)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	// RFC 9126 §2.1 step 2: Reject if request_uri is provided.
	if r.Form.Has("request_uri") {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("request_uri is not allowed in pushed authorization request"), nil)
		return
	}

	// Decode authorization request parameters.
	// Use WithIgnoreUnknownKeys() to skip client authentication fields
	// (client_secret, client_assertion, etc.) that are not in AuthRequest.
	// This is a per-decode option — it doesn't affect other plugins.
	authReq := new(protocol.AuthRequest)
	if err := p.decoder.Decode(authReq, r.Form, protocol.WithIgnoreUnknownKeys()); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error decoding auth request").WithParent(err), nil)
		return
	}

	slog.Info("PAR: decoded form",
		slog.String("request_param", truncate(authReq.RequestParam, 80)),
		slog.Any("scopes", authReq.Scopes),
		slog.String("redirect_uri", authReq.RedirectURI),
		slog.String("response_type", string(authReq.ResponseType)),
		slog.String("client_id", authReq.ClientID),
		slog.Any("form_keys", formKeys(r.Form)),
	)

	// FAPI 2.0 signed_non_repudiation: if the client is configured with a
	// request_object_signing_alg, a signed request object is required.
	if err := shared.ValidateSignedRequestObjectRequired(client, authReq.RequestParam != ""); err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	// RFC 9101 / OIDC Core §6.1: Parse and validate request object if present.
	// FAPI 2.0 requires JAR (JWT-Secured Authorization Requests), so the
	// request parameters (scope, redirect_uri, etc.) are inside the signed JWT.
	if authReq.RequestParam != "" {
		lookupClient := func(ctx context.Context, clientID string) (shared.Client, error) {
			return p.clientStore.GetClientByClientID(ctx, clientID)
		}
		if err := shared.ParseAndValidateRequestObject(r.Context(), authReq, lookupClient, p.skipTLSCertVerify, p.allowPrivateIPs); err != nil {
			slog.Error("PAR: request object validation failed", slog.Any("error", err))
			shared.WriteError(w, r, err, nil)
			return
		}
		slog.Info("PAR: request object parsed",
			slog.Any("scopes", authReq.Scopes),
			slog.String("redirect_uri", authReq.RedirectURI),
			slog.String("response_type", string(authReq.ResponseType)),
			slog.String("client_id", authReq.ClientID),
		)
		// RFC 9126 §2: A client MUST NOT include a request_uri parameter
		// in the request to the PAR endpoint. This includes request_uri
		// inside a request object.
		if authReq.RequestURI != "" {
			shared.WriteError(w, r, protocol.ErrInvalidRequestObject().WithDescription("request_uri is not allowed in pushed authorization request"), nil)
			return
		}
	} else {
		slog.Info("PAR: no request object, using direct params")
	}

	// RFC 9449 §10.1 / DPOP-10.1: DPoP code binding at the PAR endpoint.
	//
	// Two mechanisms (both MUST be supported):
	//   1. dpop_jkt parameter in the PAR request body (or request object).
	//   2. DPoP proof header in the PAR request — the AS MUST behave as if
	//      the proof's JWK thumbprint was provided via dpop_jkt.
	//
	// If both are present, they MUST match; otherwise the request is rejected.
	dpopProof := shared.DPoPFromContext(ctx)
	if dpopProof != nil && authReq.DPoPJKT != "" {
		// Both mechanisms present — thumbprints MUST match.
		if dpopProof.JWKThumbprint() != authReq.DPoPJKT {
			shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("dpop_jkt does not match DPoP proof JWK thumbprint"), nil)
			return
		}
	}
	if authReq.DPoPJKT == "" && dpopProof != nil {
		// Only DPoP header present — treat as if dpop_jkt was provided.
		authReq.DPoPJKT = dpopProof.JWKThumbprint()
	}

	// RFC 9126 §3: Validate pushed authorization request parameters
	// before storing. This provides fail-fast behavior for clients.
	// FAPI 2.0 request objects may omit scope — default to "openid".
	if err := shared.ValidateAuthRequestParams(client, authReq, protocol.ScopeOpenID); err != nil {
		slog.Error("PAR: validation failed", slog.Any("error", err))
		shared.WriteError(w, r, err, nil)
		return
	}

	// DEBUG: trace scopes before storing PAR
	slog.Info("PAR: before StorePushedAuthRequest",
		slog.Any("scopes", authReq.Scopes),
		slog.String("client_id", authReq.ClientID),
		slog.String("redirect_uri", authReq.RedirectURI),
	)

	requestURI, err := p.store.StorePushedAuthRequest(r.Context(), client.GetID(), authReq, p.lifetime)
	if err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error storing pushed auth request"), nil)
		return
	}

	resp := &protocol.PushedAuthResponse{
		RequestURI: requestURI,
		ExpiresIn:  int(p.lifetime.Seconds()),
	}

	shared.JSONResponse(w, resp, http.StatusCreated)
}

// authenticateClient authenticates the client using the appropriate method.
// Supports client_secret_basic, client_secret_post, private_key_jwt, and none.
func (p *Plugin) authenticateClient(r *http.Request) (storm.Client, error) {
	// RFC 7523 §2.2 / OIDC Core §9: client_assertion takes precedence.
	if assertionType := r.Form.Get("client_assertion_type"); assertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		assertion := r.Form.Get("client_assertion")
		if assertion == "" {
			return nil, protocol.ErrInvalidClient().WithDescription("client_assertion is missing")
		}
		issuer := shared.IssuerFromContext(r.Context())
		tokenEndpoint := shared.EndpointURL(r.Context(), protocol.NewEndpoint("/token"))
		parEndpoint := shared.EndpointURL(r.Context(), protocol.NewEndpoint("/par"))
		// Adapt storm.ClientStore.GetClientByClientID to shared.Client lookup.
		getClient := func(ctx context.Context, clientID string) (shared.Client, error) {
			return p.clientStore.GetClientByClientID(ctx, clientID)
		}
		getAudiences := func(client shared.Client) []string {
			// FAPI 2.0 §5.3.2.1: aud must be issuer URL only.
			if fapiClient, ok := client.(interface{ FAPIProfile() bool }); ok && fapiClient.FAPIProfile() {
				return []string{issuer}
			}
			// RFC 9126 §3: PAR endpoint accepts issuer, token endpoint, or PAR endpoint.
			return []string{issuer, tokenEndpoint, parEndpoint}
		}
		// DEBUG: log assertion aud vs allowed audiences
		req := new(protocol.JWTTokenRequest)
		if _, parseErr := protocol.ParseToken(assertion, req); parseErr == nil {
			slog.Info("[DEBUG] PAR authenticateClient", "issuer", issuer, "assertion_aud", req.Audience)
		}
		client, err := shared.AuthenticatePrivateKeyJWT(r, getClient, assertion, getAudiences, p.skipTLSCertVerify, p.allowPrivateIPs)
		if err != nil {
			return nil, err
		}
		// shared.AuthenticatePrivateKeyJWT returns shared.Client; we need storm.Client.
		// Since the lookup came from storm.ClientStore, re-cast is safe.
		return client.(storm.Client), nil
	}

	// Fall back to client_id + client_secret authentication.
	clientID, clientSecret, err := validatePARRequest(r)
	if err != nil {
		return nil, err
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithParent(err)
	}

	if client.AuthMethod() != protocol.AuthMethodNone {
		if err := p.clientStore.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			return nil, err
		}
	}

	return client, nil
}
