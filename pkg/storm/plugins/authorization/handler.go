package authorization

// HTTP handlers for the authorization plugin:
//   - handleAuthorize — GET/POST /authorize (RFC 6749 §3.1, OIDC Core §3.1.1)
//   - handleCallback  — GET /authorize/callback (internal login-UI callback)
//   - handleAccept    — POST /authorize/complete (challenge-based REST API)
//   - handleReject    — POST /authorize/reject (challenge-based REST API)

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

// --- authorize handler ---

func (p *Plugin) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// DEBUG: log every request hitting the authorize endpoint
	slog.Info("handleAuthorize: REQUEST RECEIVED",
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)
	ctx, span := shared.TracerSpan(r.Context(), p.tracer, "authorization.authorize")
	defer span.End()
	if p.jarmSigner != nil {
		ctx = contextWithJARMSigner(ctx, p.jarmSigner)
	}
	r = r.WithContext(ctx)

	if err := r.ParseForm(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cannot parse form")
		writeAuthError(w, r, "", "", "", protocol.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err))
		return
	}

	authReq, err := parseAuthorizeRequest(r.Form, p.decoder)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cannot parse auth request")
		writeAuthError(w, r, "", "", "", protocol.ErrInvalidRequest().WithDescription("cannot parse auth request").WithParent(err))
		return
	}

	span.SetAttributes(
		attribute.String("client_id", authReq.ClientID),
		attribute.String("response_type", string(authReq.ResponseType)),
		attribute.String("redirect_uri", authReq.RedirectURI),
		attribute.StringSlice("scopes", []string(authReq.Scopes)),
	)

	// DEBUG: trace scope after initial form parsing
	slog.Info("authorize: after parseAuthorizeRequest",
		slog.Any("scopes", authReq.Scopes),
		slog.String("client_id", authReq.ClientID),
		slog.String("request_param_present", fmt.Sprintf("%v", authReq.RequestParam != "")),
		slog.String("request_uri", authReq.RequestURI),
	)

	// Resolve effective response mode: explicit > implicit default from response_type.
	// Per OAuth 2.0 Multiple Response Types §2.1, hybrid/implicit flows default to fragment.
	// NOTE: This is calculated AFTER request_uri/PAR resolution so that response_mode
	// from the request object or PAR request is properly reflected.
	// (initial calculation removed — moved below request_uri/PAR resolution)

	// RFC 9101 §5.2.1: request and request_uri MUST NOT be used together.
	// Note: Before the client is resolved, we cannot validate redirect_uri
	// against registered URIs. Per OIDC Core §3.1.2.6, we must not redirect
	// errors to an unvalidated redirect_uri. These early errors are shown
	// directly to the user.
	if authReq.RequestParam != "" && authReq.RequestURI != "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("request and request_uri must not be used together"), nil)
		return
	}

	// Parse Request Object (OIDC Core §6.1, RFC 9101)
	if authReq.RequestParam != "" {
		if err := p.applyRequestObject(r.Context(), authReq); err != nil {
			shared.WriteError(w, r, err, nil)
			return
		}
		slog.Info("authorize: after applyRequestObject",
			slog.Any("scopes", authReq.Scopes),
			slog.String("client_id", authReq.ClientID),
		)
	}

	// Resolve request_uri (OIDC Core §6.1, RFC 9101 §5.2)
	if authReq.RequestURI != "" {
		if strings.HasPrefix(authReq.RequestURI, "http://") || strings.HasPrefix(authReq.RequestURI, "https://") {
			// request_uri is a URL pointing to a signed JWT request object (OIDC Core §6.1)
			if err := p.applyRequestURI(r.Context(), authReq); err != nil {
				shared.WriteError(w, r, err, nil)
				return
			}
			slog.Info("authorize: after applyRequestURI",
				slog.Any("scopes", authReq.Scopes),
				slog.String("client_id", authReq.ClientID),
			)
		} else {
			// request_uri is a PAR reference (RFC 9101 §5.2)
			if p.parStore == nil {
				shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("request_uri not supported"), nil)
				return
			}
			if err := p.applyPARRequest(r.Context(), authReq); err != nil {
				shared.WriteError(w, r, err, nil)
				return
			}
			slog.Info("authorize: after applyPARRequest",
				slog.Any("scopes", authReq.Scopes),
				slog.String("client_id", authReq.ClientID),
				slog.String("redirect_uri", authReq.RedirectURI),
			)
		}
	}

	// Resolve effective response mode AFTER request_uri/PAR resolution.
	resolvedMode := resolveResponseMode(authReq.ResponseMode, authReq.ResponseType)
	slog.Info("authorize: resolved response mode",
		slog.String("authReq_response_mode", string(authReq.ResponseMode)),
		slog.String("authReq_response_type", string(authReq.ResponseType)),
		slog.String("resolved_mode", string(resolvedMode)),
		slog.String("client_id", authReq.ClientID),
	)

	if authReq.ClientID == "" {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("client_id is missing"), nil)
		return
	}
	if authReq.RedirectURI == "" {
		// No redirect_uri means we cannot redirect; write JSON error.
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("redirect_uri is missing"), nil)
		return
	}

	client, err := p.clientStore.GetClientByClientID(r.Context(), authReq.ClientID)
	if err != nil {
		// Client not found: cannot validate redirect_uri, so do not redirect.
		shared.WriteError(w, r, protocol.ErrInvalidRequestRedirectURI().WithDescription("unable to retrieve client").WithParent(err), nil)
		return
	}
	// Store clientID in context for JARM error responses.
	if authReq.ClientID != "" {
		r = r.WithContext(contextWithJARMClientID(r.Context(), authReq.ClientID))
	}
	// Store client's preferred signing algorithm for JARM signing.
	if alg := shared.ResolvePreferredSigningAlg(client); alg != "" {
		r = r.WithContext(shared.ContextWithJARMPreferredAlg(r.Context(), alg))
	}
	// Per OIDC Core §3.1.2.4: if redirect_uri is not registered, the OP
	// MUST NOT redirect to it and MUST display an error directly.
	redirectURIErr := validateRedirectURI(client, authReq.RedirectURI, authReq.ResponseType)
	if redirectURIErr != nil {
		shared.WriteError(w, r, redirectURIErr, nil)
		return
	}

	// RFC 9449 §7.1: if the authorization request includes a DPoP proof
	// header and dpop_jkt was not already set (e.g. from PAR data or
	// request object), capture the JWK thumbprint for code binding.
	if authReq.DPoPJKT == "" {
		if dpopProof := shared.DPoPFromContext(r.Context()); dpopProof != nil {
			authReq.DPoPJKT = dpopProof.JWKThumbprint()
			slog.Info("authorize: captured DPoP JKT from proof",
				slog.String("jkt", authReq.DPoPJKT),
			)
		}
	}

	// FAPI 2.0 §5.3.1: the authorization server SHALL require the use of
	// PAR or a request object. Reject plain query-string requests for
	// FAPI 2.0 clients.
	if fapiClient, ok := client.(interface{ FAPIProfile() bool }); ok && fapiClient.FAPIProfile() {
		if authReq.RequestURI == "" && authReq.RequestParam == "" {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.ErrInvalidRequest().WithDescription("FAPI 2.0 requires a request object or PAR (request_uri)"))
			return
		}
	}

	// FAPI 2.0 signed_non_repudiation: if the client is configured with a
	// request_object_signing_alg, a signed request object is required.
	// For PAR-based requests the request object was already validated at the
	// PAR endpoint, so we only enforce this on direct authorization requests.
	if authReq.RequestURI == "" {
		if err := shared.ValidateSignedRequestObjectRequired(client, authReq.RequestParam != ""); err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode, err)
			return
		}
	}

	// Now that redirect_uri is validated, remaining errors can be
	// safely redirected to the registered URI.
	slog.Info("authorize: before validateAuthRequestParamsExceptRedirectURI",
		slog.Any("scopes", authReq.Scopes),
		slog.Int("scopes_len", len(authReq.Scopes)),
	)
	if err := validateAuthRequestParamsExceptRedirectURI(client, authReq); err != nil {
		slog.Error("authorize: validation failed",
			slog.Any("error", err),
			slog.Any("scopes", authReq.Scopes),
		)
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode, err)
		return
	}
	slog.Info("authorize: after validateAuthRequestParamsExceptRedirectURI",
		slog.Any("scopes", authReq.Scopes),
		slog.Int("scopes_len", len(authReq.Scopes)),
	)

	// Reject plain PKCE unless explicitly allowed (OAuth 2.1 §4.1.1).
	// S256 is always accepted; plain requires the server to opt in.
	if !p.allowPlainPKCE && authReq.CodeChallengeMethod == protocol.CodeChallengeMethodPlain {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
			protocol.ErrInvalidRequest().WithDescription("plain code_challenge_method is not allowed; use S256"))
		return
	}

	// Validate id_token_hint (OIDC Core §3.1.2.2)
	var idTokenHintSubject string
	if authReq.IDTokenHint != "" {
		subject, _, err := p.validateIDTokenHint(r.Context(), authReq.IDTokenHint)
		if err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.ErrInvalidRequest().WithDescription("invalid id_token_hint").WithParent(err))
			return
		}
		idTokenHintSubject = subject
		// Note: subject matching is delegated to the login UI, which can
		// re-parse the id_token_hint to extract the sub claim and compare
		// it against the authenticated user. Per OIDC Core §3.1.2.2, if
		// the identified user does not match, the OP SHOULD return an error.
	}

	// Implicit/hybrid flow guard: disabled by default per OAuth 2.1
	if !p.enableImplicit && (isImplicitResponseType(authReq.ResponseType) || isHybridResponseType(authReq.ResponseType)) {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
			protocol.ErrInvalidRequest().WithDescription("implicit/hybrid flow is disabled"))
		return
	}

	// Invoke AuthorizeValidator extension point if client implements it.
	if avc, ok := client.(AuthorizeValidatorClient); ok {
		if err := avc.AuthorizeValidator().ValidateAuthRequest(client, authReq); err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode, err)
			return
		}
	}

	// OIDC Core §3.1.2.6: prompt=none MUST NOT display any UI.
	// If no session exists, return login_required immediately.
	// If a session exists, auto-complete the auth request with the
	// original auth_time and skip the login UI entirely.
	//
	// Session resolution order:
	//   1. session cookie (browser clients)
	//   2. id_token_hint subject lookup (API / conformance-test clients)
	//   3. login_hint subject lookup
	//
	// If both cookie and id_token_hint are present, the subjects MUST match;
	// otherwise the request is treated as unauthenticated per OIDC Core §3.1.2.2.
	if slices.Contains(authReq.Prompt, protocol.PromptNone) {
		if p.sessionProvider == nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.ErrLoginRequired().WithDescription("prompt=none but no session provider configured"))
			return
		}

		cookieSubject, cookieAuthTime, cookieSID, cookieOK := p.sessionProvider.GetSession(r.Context(), r, authReq.ClientID)

		// Resolve subject from hints when cookie is absent or to cross-check.
		var hintSubject string
		if idTokenHintSubject != "" {
			hintSubject = idTokenHintSubject
		} else if authReq.LoginHint != "" {
			hintSubject = authReq.LoginHint
		}

		var subject string
		var authTime time.Time
		var sid string
		var ok bool

		switch {
		case cookieOK && hintSubject != "":
			// Both cookie and hint present — subjects must match.
			if cookieSubject == hintSubject {
				subject, authTime, sid, ok = cookieSubject, cookieAuthTime, cookieSID, true
			} else {
				writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
					protocol.ErrLoginRequired().WithDescription("session subject does not match id_token_hint"))
				return
			}
		case cookieOK:
			subject, authTime, sid, ok = cookieSubject, cookieAuthTime, cookieSID, true
		case hintSubject != "":
			if sessionBySubject, canLookup := p.sessionProvider.(interface {
				GetSessionBySubject(subject string) (authTime time.Time, sid string, ok bool)
			}); canLookup {
				authTime, sid, ok = sessionBySubject.GetSessionBySubject(hintSubject)
				if ok {
					subject = hintSubject
				}
			}
		}

		if !ok {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.ErrLoginRequired().WithDescription("user is not logged in"))
			return
		}

		// Auto-complete: create auth request with subject, mark done
		// with the original auth_time, then directly produce the auth
		// response — no login UI redirect.
		completer, ok := p.authStore.(storm.AutoCompleteAuthRequest)
		if !ok {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.ErrServerError().WithDescription("prompt=none requires AutoCompleteAuthRequest support"))
			return
		}
		req, err := p.authStore.CreateAuthRequest(r.Context(), authReq, subject)
		if err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.DefaultToServerError(err, "unable to save auth request"))
			return
		}
		// Store DPoP code binding if present (RFC 9449 §7.1)
		p.storeDPoPCodeBinding(r.Context(), req.GetID(), authReq.DPoPJKT)
		if err := completer.CompleteAuthRequest(r.Context(), req.GetID(), subject, authTime, sid); err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.DefaultToServerError(err, "unable to complete auth request"))
			return
		}
		completed, err := p.authStore.AuthRequestByID(r.Context(), req.GetID())
		if err != nil {
			writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
				protocol.DefaultToServerError(err, "unable to fetch completed auth request"))
			return
		}
		p.authResponse(w, r, completed)
		return
	}

	// OIDC Core §3.1.2.1: max_age specifies the allowable elapsed
	// time since the last authentication. If the session auth_time
	// is within the max_age window, skip re-authentication and
	// auto-complete with the original auth_time.
	if authReq.MaxAge != nil && p.sessionProvider != nil {
		subject, authTime, sid, ok := p.sessionProvider.GetSession(r.Context(), r, authReq.ClientID)
		if ok {
			elapsed := time.Since(authTime)
			if elapsed <= time.Duration(*authReq.MaxAge)*time.Second {
				completer, ok := p.authStore.(storm.AutoCompleteAuthRequest)
				if !ok {
					writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
						protocol.ErrServerError().WithDescription("max_age auto-complete requires AutoCompleteAuthRequest support"))
					return
				}
				req, err := p.authStore.CreateAuthRequest(r.Context(), authReq, subject)
				if err != nil {
					writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
						protocol.DefaultToServerError(err, "unable to save auth request"))
					return
				}
				// Store DPoP code binding if present (RFC 9449 §7.1)
				p.storeDPoPCodeBinding(r.Context(), req.GetID(), authReq.DPoPJKT)
				if err := completer.CompleteAuthRequest(r.Context(), req.GetID(), subject, authTime, sid); err != nil {
					writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
						protocol.DefaultToServerError(err, "unable to complete auth request"))
					return
				}
				completed, err := p.authStore.AuthRequestByID(r.Context(), req.GetID())
				if err != nil {
					writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
						protocol.DefaultToServerError(err, "unable to fetch completed auth request"))
					return
				}
				p.authResponse(w, r, completed)
				return
			}
			// max_age exceeded — fall through to login UI for re-authentication
		}
		// No session — fall through to login UI
	}

	req, err := p.authStore.CreateAuthRequest(r.Context(), authReq, "")
	if err != nil {
		writeAuthError(w, r, authReq.RedirectURI, authReq.State, resolvedMode,
			protocol.DefaultToServerError(err, "unable to save auth request"))
		return
	}
	// Store DPoP code binding if present (RFC 9449 §7.1)
	p.storeDPoPCodeBinding(r.Context(), req.GetID(), authReq.DPoPJKT)

	loginURL := client.LoginURL(req.GetID())
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// --- callback handler ---

func (p *Plugin) handleCallback(w http.ResponseWriter, r *http.Request) {
	if p.jarmSigner != nil {
		r = r.WithContext(contextWithJARMSigner(r.Context(), p.jarmSigner))
	}
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, fmt.Errorf("cannot parse form: %w", err), nil)
		return
	}

	id := r.Form.Get("id")
	if id == "" {
		shared.WriteError(w, r, errors.New("auth request callback is missing id"), nil)
		return
	}

	authReq, err := p.authStore.AuthRequestByID(r.Context(), id)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}
	// Store clientID in context for JARM error responses.
	if authReq.GetClientID() != "" {
		r = r.WithContext(contextWithJARMClientID(r.Context(), authReq.GetClientID()))
	}
	// Store client's preferred signing algorithm for JARM signing.
	if jarmClient, err := p.clientStore.GetClientByClientID(r.Context(), authReq.GetClientID()); err == nil {
		if alg := shared.ResolvePreferredSigningAlg(jarmClient); alg != "" {
			r = r.WithContext(shared.ContextWithJARMPreferredAlg(r.Context(), alg))
		}
	}

	// If the login UI passed an error (e.g. user cancelled), return it
	// via the authorization error response (JARM-aware).
	if errorParam := r.Form.Get("error"); errorParam != "" {
		description := r.Form.Get("error_description")
		if description == "" {
			description = errorParam
		}
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType()),
			protocol.ToOAuthError(errorParam).WithDescription("%s", description))
		return
	}

	if !authReq.Done() {
		writeAuthError(w, r, authReq.GetRedirectURI(), authReq.GetState(),
			resolveResponseMode(authReq.GetResponseMode(), authReq.GetResponseType()),
			protocol.ErrInteractionRequired().WithDescription("user may not be logged in"))
		return
	}

	p.authResponse(w, r, authReq)
}

// ─── challenge-based REST API handlers ────────────────────────────────

// handleAccept accepts a login challenge from an external Login UI (REST API).
//
// This is the StormEngine equivalent of Hydra's PUT /oauth2/auth/requests/login/accept.
// The Login UI authenticates the user and calls
// this endpoint to complete the authorization request.
//
// Request:  POST /authorize/complete
//
//	{ "auth_request_id": "...", "subject": "...", "auth_time": 0, "sid": "..." }
//
// Response: 200 OK
//
//	{ "redirect_to": "https://op.example.com/authorize/callback?id=..." }
//
// The Login UI should redirect the user agent to the returned redirect_to URL.
func (p *Plugin) handleAccept(w http.ResponseWriter, r *http.Request) {
	ctx, span := shared.TracerSpan(r.Context(), p.tracer, "authorization.accept")
	defer span.End()

	var req struct {
		AuthRequestID string `json:"auth_request_id"`
		Subject       string `json:"subject"`
		AuthTime      int64  `json:"auth_time,omitempty"`
		SID           string `json:"sid,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		shared.JSONResponse(w, map[string]string{
			"error":             "invalid_request",
			"error_description": "invalid request body",
		}, http.StatusBadRequest)
		return
	}
	if req.AuthRequestID == "" || req.Subject == "" {
		shared.JSONResponse(w, map[string]string{
			"error":             "invalid_request",
			"error_description": "auth_request_id and subject are required",
		}, http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.String("auth_request_id", req.AuthRequestID),
		attribute.String("subject", req.Subject),
	)

	// Verify the auth request exists.
	authReq, err := p.authStore.AuthRequestByID(ctx, req.AuthRequestID)
	if err != nil {
		span.RecordError(err)
		shared.JSONResponse(w, map[string]string{
			"error":             "invalid_request",
			"error_description": "auth request not found",
		}, http.StatusNotFound)
		return
	}

	// Idempotency: reject if the auth request is already completed.
	// This prevents replay attacks where a stolen auth_request_id is
	// used to accept the challenge a second time.
	if authReq.Done() {
		span.SetStatus(codes.Error, "auth request already completed")
		shared.JSONResponse(w, map[string]string{
			"error":             "invalid_request",
			"error_description": "auth request already completed",
		}, http.StatusConflict)
		return
	}

	// Store clientID in context for JARM error responses.
	if authReq.GetClientID() != "" {
		r = r.WithContext(contextWithJARMClientID(r.Context(), authReq.GetClientID()))
	}
	// Store client's preferred signing algorithm for JARM signing.
	if jarmClient, err := p.clientStore.GetClientByClientID(ctx, authReq.GetClientID()); err == nil {
		if alg := shared.ResolvePreferredSigningAlg(jarmClient); alg != "" {
			r = r.WithContext(shared.ContextWithJARMPreferredAlg(r.Context(), alg))
		}
	}

	// Complete the auth request via AutoCompleteAuthRequest.
	completer, ok := p.authStore.(storm.AutoCompleteAuthRequest)
	if !ok {
		span.SetStatus(codes.Error, "AutoCompleteAuthRequest not supported")
		shared.JSONResponse(w, map[string]string{
			"error":             "server_error",
			"error_description": "AutoCompleteAuthRequest not supported by storage",
		}, http.StatusInternalServerError)
		return
	}

	authTime := time.Now()
	if req.AuthTime > 0 {
		authTime = time.Unix(req.AuthTime, 0)
	}
	if err := completer.CompleteAuthRequest(ctx, req.AuthRequestID, req.Subject, authTime, req.SID); err != nil {
		span.RecordError(err)
		shared.JSONResponse(w, map[string]string{
			"error":             "server_error",
			"error_description": "failed to complete auth request",
		}, http.StatusInternalServerError)
		return
	}

	// Build the callback redirect URL.
	callbackPath := p.getRoutePath("authorize_callback", "/authorize/callback")
	redirectTo := strings.TrimRight(shared.IssuerFromContext(ctx), "/") + callbackPath + "?id=" + url.QueryEscape(req.AuthRequestID)

	span.SetAttributes(attribute.String("redirect_to", redirectTo))

	shared.JSONResponse(w, map[string]string{
		"redirect_to": redirectTo,
	}, http.StatusOK)
}

// handleReject rejects a login challenge from an external Login UI (REST API).
//
// This is the StormEngine equivalent of Hydra's PUT /oauth2/auth/requests/login/reject.
// The Login UI calls this when authentication fails
// or the user cancels.
//
// Request:  POST /authorize/reject
//
//	{ "auth_request_id": "...", "error": "access_denied", "error_description": "..." }
//
// Response: 200 OK
//
//	{ "redirect_to": "https://op.example.com/authorize/callback?id=...&error=access_denied" }
//
// The Login UI should redirect the user agent to the returned redirect_to URL.
func (p *Plugin) handleReject(w http.ResponseWriter, r *http.Request) {
	ctx, span := shared.TracerSpan(r.Context(), p.tracer, "authorization.reject")
	defer span.End()

	var req struct {
		AuthRequestID    string `json:"auth_request_id"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		shared.JSONResponse(w, map[string]string{
			"error":             "invalid_request",
			"error_description": "invalid request body",
		}, http.StatusBadRequest)
		return
	}
	if req.AuthRequestID == "" {
		shared.JSONResponse(w, map[string]string{
			"error":             "invalid_request",
			"error_description": "auth_request_id is required",
		}, http.StatusBadRequest)
		return
	}
	if req.Error == "" {
		req.Error = "access_denied"
	}

	span.SetAttributes(
		attribute.String("auth_request_id", req.AuthRequestID),
		attribute.String("error", req.Error),
	)

	// Verify the auth request exists (for redirect_uri/state extraction).
	authReq, err := p.authStore.AuthRequestByID(ctx, req.AuthRequestID)
	if err != nil {
		span.RecordError(err)
		shared.JSONResponse(w, map[string]string{
			"error":             "invalid_request",
			"error_description": "auth request not found",
		}, http.StatusNotFound)
		return
	}

	// Idempotency: cannot reject an already-completed auth request.
	if authReq.Done() {
		span.SetStatus(codes.Error, "auth request already completed")
		shared.JSONResponse(w, map[string]string{
			"error":             "invalid_request",
			"error_description": "auth request already completed",
		}, http.StatusConflict)
		return
	}

	// Store clientID in context for JARM error responses.
	if authReq.GetClientID() != "" {
		r = r.WithContext(contextWithJARMClientID(r.Context(), authReq.GetClientID()))
	}
	if jarmClient, err := p.clientStore.GetClientByClientID(ctx, authReq.GetClientID()); err == nil {
		if alg := shared.ResolvePreferredSigningAlg(jarmClient); alg != "" {
			r = r.WithContext(shared.ContextWithJARMPreferredAlg(r.Context(), alg))
		}
	}
	if p.jarmSigner != nil {
		r = r.WithContext(contextWithJARMSigner(r.Context(), p.jarmSigner))
	}

	// Build the error callback URL.
	callbackPath := p.getRoutePath("authorize_callback", "/authorize/callback")
	params := url.Values{}
	params.Set("id", req.AuthRequestID)
	params.Set("error", req.Error)
	if req.ErrorDescription != "" {
		params.Set("error_description", req.ErrorDescription)
	}
	redirectTo := strings.TrimRight(shared.IssuerFromContext(ctx), "/") + callbackPath + "?" + params.Encode()

	span.SetAttributes(attribute.String("redirect_to", redirectTo))

	shared.JSONResponse(w, map[string]string{
		"redirect_to": redirectTo,
	}, http.StatusOK)
}
