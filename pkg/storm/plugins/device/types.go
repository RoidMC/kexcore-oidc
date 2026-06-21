package device

import (
	_ "embed"
	"html/template"
	"net/http"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
	httputil "github.com/roidmc/kexcore-oidc/v2/pkg/util/http"
)

//go:embed template/device.html.tmpl
var deviceHtmlTemplate string

var deviceTmpl = template.Must(template.New("device").Parse(deviceHtmlTemplate))

// Plugin implements the OAuth 2.0 Device Authorization Grant (RFC 8628).
type Plugin struct {
	store              storm.DeviceAuthStore
	clientStore        storm.ClientStore
	clientAuth         *shared.ClientAuthHelper
	lifetime           time.Duration
	interval           time.Duration
	deviceTmpl         *template.Template
	maxUserCodeRetries int
	csrfHandler        *httputil.CookieHandler
	endpointConfigs    shared.EndpointConfigMap // endpoint configurations (optional)
}

// Config holds the dependencies for the Device plugin.
type Config struct {
	Store       storm.DeviceAuthStore
	ClientStore storm.ClientStore
	// Lifetime is the device code expiration duration (default: 15m).
	Lifetime time.Duration
	// Interval is the minimum polling interval in seconds (default: 5).
	Interval time.Duration
	// DeviceTemplate overrides the default device verification page template.
	// The template receives a map with "UserCode", "ClientID", "Scopes", "Error", "CSRFToken" keys.
	// If nil, the embedded default template is used.
	DeviceTemplate *template.Template
	// MaxUserCodeRetries limits how many times to retry user_code generation on collision.
	// Prevents infinite loops if the store is full or has high collision probability.
	// Default is 100.
	MaxUserCodeRetries int
	// CSRFKey is a 32-byte key for signing CSRF cookies on the verification page.
	// If nil, CSRF protection is disabled (not recommended for production).
	// Uses pkg/util/http CookieHandler for secure cookie handling.
	CSRFKey []byte
}

const defaultMaxUserCodeRetries = 100

// NewWithConfig creates a new Device plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	if cfg.Lifetime == 0 {
		cfg.Lifetime = 15 * time.Minute
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.MaxUserCodeRetries == 0 {
		cfg.MaxUserCodeRetries = defaultMaxUserCodeRetries
	}
	p := &Plugin{
		store:              cfg.Store,
		clientStore:        cfg.ClientStore,
		clientAuth:         storm.NewClientAuthHelper(cfg.ClientStore),
		lifetime:           cfg.Lifetime,
		interval:           cfg.Interval,
		deviceTmpl:         deviceTmpl,
		maxUserCodeRetries: cfg.MaxUserCodeRetries,
	}
	if cfg.DeviceTemplate != nil {
		p.deviceTmpl = cfg.DeviceTemplate
	}
	if len(cfg.CSRFKey) > 0 {
		p.csrfHandler = httputil.NewCookieHandler(cfg.CSRFKey, nil,
			httputil.WithPath("/device"),
			httputil.WithSameSite(http.SameSiteStrictMode),
			httputil.WithMaxAge(300),
		)
	}
	return p
}
