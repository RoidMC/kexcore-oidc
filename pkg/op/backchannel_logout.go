// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	httphelper "github.com/roidmc/kexcore-oidc/pkg/http"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
)

// BackChannelLogoutHandler receives and processes back-channel logout requests.
// A request may specify a session ID or subject identifier.
// The handler terminates the session and pushes Logout Tokens to all registered RPs.
type BackChannelLogoutHandler interface {
	Decoder() httphelper.Decoder
	Storage() Storage
	Crypto() Crypto
	Logger() *slog.Logger
}

// ---------- OP endpoint handler ----------

func backChannelLogoutHandler(handler BackChannelLogoutHandler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		BackChannelLogout(w, r, handler)
	}
}

// BackChannelLogout handles a back-channel logout request.
// It terminates the session and pushes Logout Tokens to all registered RPs.
func BackChannelLogout(w http.ResponseWriter, r *http.Request, handler BackChannelLogoutHandler) {
	ctx, span := Tracer.Start(r.Context(), "BackChannelLogout")
	defer span.End()
	r = r.WithContext(ctx)

	req, err := parseBackChannelLogoutRequest(r, handler.Decoder())
	if err != nil {
		RequestError(w, r, err, handler.Logger())
		return
	}

	// Validate that at least one of sub or sid is present.
	if req.Subject == "" && req.SessionID == "" {
		RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("either sub or sid is required"), handler.Logger())
		return
	}

	// Terminate the session.
	if err := handler.Storage().TerminateSession(ctx, req.Subject, ""); err != nil {
		handler.Logger().ErrorContext(ctx, "failed to terminate session", "error", err)
		RequestError(w, r, oidc.DefaultToServerError(err, "error terminating session"), handler.Logger())
		return
	}

	// Push Logout Tokens to all RPs that have registered a backchannel_logout_uri.
	if err := pushLogoutTokens(ctx, handler, req.Subject, req.SessionID); err != nil {
		handler.Logger().ErrorContext(ctx, "failed to push logout tokens", "error", err)
	}

	// Respond with 200 OK.
	w.WriteHeader(http.StatusOK)
}

// ---------- Request parsing ----------

// BackChannelLogoutRequest represents an OP-initiated back-channel logout request.
type BackChannelLogoutRequest struct {
	Subject    string `schema:"sub"`
	SessionID  string `schema:"sid"`
	LogoutHint string `schema:"logout_hint"`
}

func parseBackChannelLogoutRequest(r *http.Request, decoder httphelper.Decoder) (*BackChannelLogoutRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	req := new(BackChannelLogoutRequest)
	err = decoder.Decode(req, r.Form)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	return req, nil
}

// ---------- Push logic ----------

// pushLogoutTokens generates and pushes a Logout Token to each RP that has
// registered a backchannel_logout_uri.
//
// TODO: The OIDC spec encourages sending logout requests in parallel (Section 2.3).
// Currently requests are sent sequentially.
// TODO: Logout Token encryption: the spec says "A Logout Token MUST be signed
// and MAY also be encrypted" (Section 2.4). Currently only signing is implemented.
// If encrypted, the iss claim SHOULD be replicated in JWT header params.
func pushLogoutTokens(ctx context.Context, handler BackChannelLogoutHandler, sub, sid string) error {
	issuer := IssuerFromContext(ctx)
	if issuer == "" {
		return errors.New("no issuer in context")
	}

	signingKey, err := handler.Storage().SigningKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to get signing key: %w", err)
	}
	signer, err := SignerFromKey(signingKey)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	// Check if storage supports back-channel logout client discovery.
	bclStorage, ok := handler.Storage().(BackChannelLogoutStorage)
	if !ok {
		return errors.New("storage does not implement BackChannelLogoutStorage")
	}

	clients, err := bclStorage.ClientsForSession(ctx, sub, sid)
	if err != nil {
		return fmt.Errorf("failed to get clients for session: %w", err)
	}

	for _, client := range clients {
		bclClient, ok := client.(BackChannelLogoutClient)
		if !ok {
			continue
		}
		uri := bclClient.BackChannelLogoutURI()
		if uri == "" {
			continue
		}

		logoutToken, err := createLogoutToken(issuer, sub, sid, client.GetID(), signer)
		if err != nil {
			handler.Logger().ErrorContext(ctx, "failed to create logout token", "client_id", client.GetID(), "error", err)
			continue
		}

		if err := sendLogoutToken(ctx, uri, logoutToken, handler.Logger()); err != nil {
			handler.Logger().ErrorContext(ctx, "failed to send logout token", "client_id", client.GetID(), "uri", uri, "error", err)
			continue
		}
	}

	return nil
}

// createLogoutToken creates a signed JWT Logout Token.
//
// TODO: The OIDC spec RECOMMENDS setting the JWT header typ="logout+jwt"
// to explicitly type the token and prevent cross-JWT confusion.
// Currently the Signer does not support custom JWT header parameters.
func createLogoutToken(issuer, sub, sid, audience string, signer *crypto.Signer) (string, error) {
	now := time.Now()
	claims := &oidc.LogoutTokenClaims{
		Issuer:     issuer,
		Subject:    sub,
		Audience:   oidc.Audience{audience},
		IssuedAt:   oidc.FromTime(now),
		Expiration: oidc.FromTime(now.Add(5 * time.Minute)),
		JWTID:      fmt.Sprintf("%s-%d", audience, now.UnixNano()),
		SessionID:  sid,
		Events: map[string]any{
			oidc.BackChannelLogoutEventKey: struct{}{},
		},
	}
	return crypto.Sign(claims, signer)
}

// sendLogoutToken sends a Logout Token to the RP's backchannel_logout_uri
// via HTTP POST with form-encoded body (logout_token=xxx).
func sendLogoutToken(ctx context.Context, uri string, token string, logger *slog.Logger) error {
	data := url.Values{}
	data.Set("logout_token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("received non-2xx status: %d", resp.StatusCode)
	}

	logger.InfoContext(ctx, "logout token sent successfully", "uri", uri, "status", resp.StatusCode)
	return nil
}

// ---------- Storage interface extension ----------

// BackChannelLogoutStorage is an optional extension that Storage implementations
// can adopt to support back-channel logout. The OP uses this to discover which
// clients have active sessions for a given user/session.
type BackChannelLogoutStorage interface {
	Storage

	// ClientsForSession returns all clients that have an active session
	// for the given subject and/or session ID. At least one of sub or sid
	// must be provided.
	ClientsForSession(ctx context.Context, sub, sid string) ([]Client, error)
}
