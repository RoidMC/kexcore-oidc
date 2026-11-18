package backchannel

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/roidmc/kexcore-oidc/v3/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm"
)

// createLogoutToken creates a logout token JWT (OIDC Back-Channel Logout §2.4).
//
// Required claims per RFC:
//   - iss: Issuer Identifier
//   - aud: Audience(s) - the client_id
//   - iat: Issued at time
//   - exp: Expiration time
//   - jti: Unique identifier
//   - events: {"http://schemas.openid.net/event/backchannel-logout": {}}
//
// Optional claims:
//   - sub: Subject Identifier (MUST contain sub and/or sid)
//   - sid: Session ID (MUST contain sub and/or sid)
//
// Prohibited claims:
//   - nonce: MUST NOT be present
func createLogoutToken(issuer, subject, audience, sid string, signingKey storm.SigningKey) (string, error) {
	if signingKey == nil {
		return "", fmt.Errorf("no signing key available")
	}

	// Per RFC: MUST contain either sub or sid, MAY contain both
	if subject == "" && sid == "" {
		return "", fmt.Errorf("logout token must contain sub or sid")
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss": issuer,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": fmt.Sprintf("lt_%d", now.UnixNano()),
		"events": map[string]any{
			protocol.BackChannelLogoutEventKey: map[string]any{},
		},
	}
	if subject != "" {
		claims["sub"] = subject
	}
	if sid != "" {
		claims["sid"] = sid
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// Sign through the crypto provider registry so HSM/KMS overrides apply.
	signer, err := crypto.NewSigner(signingKey.Algorithm(), signingKey.Key(), signingKey.ID())
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}
	signer.SetTokenType("logout+jwt")
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("JWS signing failed: %w", err)
	}
	return signed, nil
}

// sendLogoutToken sends a logout token to a client's backchannel_logout_uri.
// Per OIDC Back-Channel Logout §2.5, the token is sent as application/x-www-form-urlencoded.
// The caller must provide a non-nil HTTP client.
func sendLogoutToken(uri, logoutToken string, logger *slog.Logger, client *http.Client) {
	form := url.Values{}
	form.Set("logout_token", logoutToken)

	resp, err := client.PostForm(uri, form)
	if err != nil {
		logger.Error("failed to send logout token to client",
			slog.String("uri", uri),
			slog.Any("error", err),
		)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		logger.Warn("client returned error for logout token",
			slog.String("uri", uri),
			slog.Int("status_code", resp.StatusCode),
		)
	}
}
