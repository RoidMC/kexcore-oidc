package device

import (
	_ "embed"
	"html/template"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

//go:embed template/device.html.tmpl
var deviceHtmlTemplate string

var deviceTmpl = template.Must(template.New("device").Parse(deviceHtmlTemplate))

// Plugin implements the OAuth 2.0 Device Authorization Grant (RFC 8628).
type Plugin struct {
	store       storm.DeviceAuthStore
	clientStore storm.ClientStore
	tokenStore  storm.TokenStore
	keyStore    storm.KeyStore
	lifetime    time.Duration
	interval    time.Duration
	deviceTmpl  *template.Template
}

// Config holds the dependencies for the Device plugin.
type Config struct {
	Store       storm.DeviceAuthStore
	ClientStore storm.ClientStore
	TokenStore  storm.TokenStore
	KeyStore    storm.KeyStore
	// Lifetime is the device code expiration duration (default: 15m).
	Lifetime time.Duration
	// Interval is the minimum polling interval in seconds (default: 5).
	Interval time.Duration
	// DeviceTemplate overrides the default device verification page template.
	// The template receives a map with "UserCode", "ClientID", "Scopes", "Error" keys.
	// If nil, the embedded default template is used.
	DeviceTemplate *template.Template
}

// NewWithConfig creates a new Device plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	if cfg.Lifetime == 0 {
		cfg.Lifetime = 15 * time.Minute
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	p := &Plugin{
		store:       cfg.Store,
		clientStore: cfg.ClientStore,
		tokenStore:  cfg.TokenStore,
		keyStore:    cfg.KeyStore,
		lifetime:    cfg.Lifetime,
		interval:    cfg.Interval,
		deviceTmpl:  deviceTmpl,
	}
	if cfg.DeviceTemplate != nil {
		p.deviceTmpl = cfg.DeviceTemplate
	}
	return p
}
