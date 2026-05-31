// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/client"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// BackChannelLogoutHandler is an HTTP handler that receives and validates
// Logout Tokens at an RP's backchannel_logout_uri endpoint.
//
// Usage:
//
//	mux.Handle("/backchannel_logout", rp.BackChannelLogoutHandler(verifier, onLogout))
type BackChannelLogoutHandler struct {
	verifier *LogoutTokenVerifier
	onLogout LogoutCallback
}

// LogoutCallback is called after a valid Logout Token is received.
// The RP should use the sub and/or sid claims to terminate the appropriate sessions.
type LogoutCallback func(ctx context.Context, claims *oidc.LogoutTokenClaims) error

// LogoutTokenVerifier verifies Logout Tokens according to the spec.
type LogoutTokenVerifier struct {
	// Issuer is the expected OP issuer.
	Issuer string

	// ClientID is the RP's client_id (used for audience verification).
	ClientID string

	// KeySet is the OP's public key set for signature verification.
	KeySet protocol.KeySet

	// SupportedSignAlgs are the accepted signature algorithms.
	SupportedSignAlgs []string
}

// NewBackChannelLogoutHandler creates a handler for the backchannel_logout endpoint.
func NewBackChannelLogoutHandler(verifier *LogoutTokenVerifier, callback LogoutCallback) http.Handler {
	return &BackChannelLogoutHandler{
		verifier: verifier,
		onLogout: callback,
	}
}

// ServeHTTP handles incoming back-channel logout requests.
func (h *BackChannelLogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := client.Tracer.Start(r.Context(), "BackChannelLogout")
	defer span.End()
	r = r.WithContext(ctx)

	// Parse the form body to extract the logout_token parameter.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	logoutToken := r.Form.Get("logout_token")
	if logoutToken == "" {
		http.Error(w, "missing logout_token", http.StatusBadRequest)
		return
	}

	claims, err := VerifyLogoutToken(ctx, logoutToken, h.verifier)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid logout token: %v", err), http.StatusBadRequest)
		return
	}

	if h.onLogout != nil {
		if err := h.onLogout(ctx, claims); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// VerifyLogoutToken validates a Logout Token according to the rules in
// Section 2.6 of OpenID Connect Back-Channel Logout 1.0.
func VerifyLogoutToken(ctx context.Context, token string, v *LogoutTokenVerifier) (*oidc.LogoutTokenClaims, error) {
	ctx, span := client.Tracer.Start(ctx, "VerifyLogoutToken")
	defer span.End()

	var claims oidc.LogoutTokenClaims

	// 1. Parse the JWT payload.
	payload, err := protocol.ParseToken(token, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse logout token: %w", err)
	}

	// 2. Verify the audience contains this client.
	if err := verifyLogoutAudience(&claims, v.ClientID); err != nil {
		return nil, err
	}

	// 3. Verify the issuer matches the expected OP.
	if claims.Issuer != v.Issuer {
		return nil, fmt.Errorf("%w: expected %q but was %q", protocol.ErrIssuerInvalid, v.Issuer, claims.Issuer)
	}

	// 4. Verify the signature.
	if err := protocol.CheckSignature(ctx, token, payload, &claims, v.SupportedSignAlgs, v.KeySet); err != nil {
		return nil, err
	}

	// 5. Verify the events claim contains the backchannel-logout event.
	if claims.Events == nil {
		return nil, errors.New("missing events claim")
	}
	if _, ok := claims.Events[oidc.BackChannelLogoutEventKey]; !ok {
		return nil, fmt.Errorf("missing required event: %s", oidc.BackChannelLogoutEventKey)
	}

	// 6. Verify that nonce is NOT present.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err == nil {
		if _, hasNonce := raw["nonce"]; hasNonce {
			return nil, errors.New("nonce claim is prohibited in Logout Token")
		}
	}

	// 7. Verify iat and exp.
	if err := protocol.CheckIssuedAt(&claims, 0, time.Second); err != nil {
		return nil, err
	}
	if err := protocol.CheckExpiration(&claims, 0); err != nil {
		return nil, err
	}

	// 8. Verify at least one of sub or sid is present.
	if claims.Subject == "" && claims.SessionID == "" {
		return nil, errors.New("either sub or sid must be present")
	}

	return &claims, nil
}

func verifyLogoutAudience(claims *oidc.LogoutTokenClaims, expectedClientID string) error {
	for _, aud := range claims.Audience {
		if aud == expectedClientID {
			return nil
		}
	}
	return fmt.Errorf("%w: expected %q", protocol.ErrAudience, expectedClientID)
}
