// Package backchannel implements the OIDC Back-Channel Logout plugin.
//
// It handles POST /backchannel_logout (OIDC Back-Channel Logout §4),
// allowing the OP to send logout tokens to RPs via back-channel.
package backchannel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin implements the OIDC Back-Channel Logout endpoint.
type Plugin struct {
	store    storm.BackChannelStore
	crypto   storm.UniCrypto
	keyStore storm.KeyStore
}

// Config holds the dependencies for the BackChannel plugin.
type Config struct {
	Store    storm.BackChannelStore
	Crypto   storm.UniCrypto
	KeyStore storm.KeyStore
}

// New creates a new BackChannel plugin.
func New(cfg Config) *Plugin {
	return &Plugin{
		store:    cfg.Store,
		crypto:   cfg.Crypto,
		keyStore: cfg.KeyStore,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "backchannel" }

// Register installs the POST /backchannel_logout route.
//
// OIDC standard endpoint: POST /backchannel_logout (OIDC Back-Channel Logout §4)
func (p *Plugin) Register(r chi.Router) {
	r.Post("/backchannel_logout", p.handle)
}

// Contribute returns the discovery fields for the backchannel logout endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"backchannel_logout_supported":         true,
		"backchannel_logout_session_supported": true,
	}
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	// Back-channel logout is typically initiated by the OP, not by external clients.
	// This endpoint receives logout notifications and pushes logout tokens to RPs.
	//
	// The actual logout token creation and delivery is handled internally
	// when a session is terminated (e.g., via endsession plugin).

	// For now, this is a placeholder that acknowledges the request.
	// The real back-channel logout logic involves:
	// 1. Receiving a logout token from another OP or internal trigger
	// 2. Validating the logout token
	// 3. Finding affected RPs via ClientsForSession
	// 4. Pushing logout tokens to each RP's backchannel_logout_uri

	shared.JSONResponse(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// PushLogoutTokens sends logout tokens to all RPs that have sessions
// for the given subject and session ID (OIDC Back-Channel Logout §2.5).
func PushLogoutTokens(ctx context.Context, store storm.BackChannelStore, issuer string, signingKey storm.SigningKey, subject, sid string) error {
	clients, err := store.ClientsForSession(ctx, subject, sid)
	if err != nil {
		return err
	}

	for _, client := range clients {
		type backchannelURIProvider interface {
			BackChannelLogoutURI() string
		}
		bc, ok := client.(backchannelURIProvider)
		if !ok {
			continue
		}
		uri := bc.BackChannelLogoutURI()
		if uri == "" {
			continue
		}

		logoutToken, err := createLogoutToken(issuer, subject, client.GetID(), sid, signingKey)
		if err != nil {
			continue
		}

		go sendLogoutToken(uri, logoutToken)
	}

	return nil
}

// createLogoutToken creates a logout token JWT (OIDC Back-Channel Logout §2.4).
func createLogoutToken(issuer, subject, audience, sid string, signingKey storm.SigningKey) (string, error) {
	if signingKey == nil {
		return "", fmt.Errorf("no signing key available")
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": fmt.Sprintf("lt_%d", now.UnixNano()),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	if sid != "" {
		claims["sid"] = sid
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	alg, err := algorithmToJWA(signingKey.Algorithm())
	if err != nil {
		return "", fmt.Errorf("unsupported signing algorithm %q: %w", signingKey.Algorithm(), err)
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.AlgorithmKey, alg)
	if signingKey.ID() != "" {
		_ = headers.Set(jws.KeyIDKey, signingKey.ID())
	}
	signed, err := jws.Sign(payload, jws.WithKey(alg, signingKey.Key(), jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("JWS signing failed: %w", err)
	}
	return string(signed), nil
}

// sendLogoutToken sends a logout token to a client's backchannel_logout_uri.
func sendLogoutToken(uri, logoutToken string) {
	form := url.Values{}
	form.Set("logout_token", logoutToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(uri, form)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// algorithmToJWA converts a string algorithm name to jwa.SignatureAlgorithm.
func algorithmToJWA(alg string) (jwa.SignatureAlgorithm, error) {
	if jwaAlg, ok := jwa.LookupSignatureAlgorithm(alg); ok {
		return jwaAlg, nil
	}
	unknown, _ := jwa.LookupSignatureAlgorithm(alg)
	return unknown, fmt.Errorf("unknown algorithm: %s", alg)
}
