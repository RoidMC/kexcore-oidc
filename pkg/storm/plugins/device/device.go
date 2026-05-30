// Package device implements the OAuth 2.0 Device Authorization Grant plugin.
//
// It handles POST /device_authorization (RFC 8628 §3.1) and the
// device_code grant type on the token endpoint.
package device

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"reflect"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
	"github.com/roidmc/kexcore-oidc/pkg/util/codec"
)

// Plugin implements the Device Authorization Grant.
type Plugin struct {
	store       storm.DeviceAuthStore
	clientStore storm.ClientStore
	converters  map[reflect.Type]codec.Converter
	lifetime    time.Duration
}

// Config holds the dependencies for the Device plugin.
type Config struct {
	Store       storm.DeviceAuthStore
	ClientStore storm.ClientStore
	Converters  map[reflect.Type]codec.Converter
	Lifetime    time.Duration
}

// New creates a new Device plugin.
func New(cfg Config) *Plugin {
	if cfg.Lifetime == 0 {
		cfg.Lifetime = 15 * time.Minute
	}
	return &Plugin{
		store:       cfg.Store,
		clientStore: cfg.ClientStore,
		converters:  cfg.Converters,
		lifetime:    cfg.Lifetime,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "device" }

// Register installs the POST /device_authorization route.
//
// OAuth 2.0 standard endpoint: POST /device_authorization (RFC 8628 §3.1)
func (p *Plugin) Register(r chi.Router) {
	r.Post("/device_authorization", p.handle)
}

// Contribute returns the discovery fields for the device authorization endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"device_authorization_endpoint": shared.IssuerURL(ctx, "/device_authorization"),
	}
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")

	// Authenticate the client
	client, err := p.clientStore.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		shared.WriteError(w, r, protocol.ErrInvalidClient().WithParent(err), nil)
		return
	}

	if client.AuthMethod() != protocol.AuthMethodNone {
		if err := p.clientStore.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			shared.WriteError(w, r, err, nil)
			return
		}
	}

	scopes := r.Form["scope"]
	deviceCode := generateRandomCode(32)
	userCode := generateRandomUserCode(8)

	if err := p.store.StoreDeviceAuthorization(r.Context(), clientID, deviceCode, userCode, time.Now().Add(p.lifetime), scopes); err != nil {
		shared.WriteError(w, r, protocol.DefaultToServerError(err, "error storing device authorization"), nil)
		return
	}

	issuer := shared.IssuerFromContext(r.Context())

	resp := &oidc.DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         issuer + "/device",
		VerificationURIComplete: issuer + "/device?user_code=" + userCode,
		ExpiresIn:               int(p.lifetime.Seconds()),
		Interval:                5,
	}

	shared.JSONResponse(w, resp, http.StatusOK)
}

func generateRandomCode(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateRandomUserCode(length int) string {
	const charset = "BCDFGHJKLMNPQRSTVWXYZ"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}
