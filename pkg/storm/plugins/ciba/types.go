package ciba

import (
	_ "embed"
	"html/template"
	"net/http"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
	httputil "github.com/roidmc/kexcore-oidc/v2/pkg/util/http"
)

//go:embed template/ciba.html.tmpl
var cibaHtmlTemplate string

var cibaTmpl = template.Must(template.New("ciba").Parse(cibaHtmlTemplate))

// Plugin implements the OpenID Connect Client-Initiated Backchannel Authentication (CIBA) protocol.
//
// CIBA Core 1.0 §7 — Backchannel Authentication Endpoint
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-7
type Plugin struct {
	store             storm.CIBAStore
	clientStore       storm.ClientStore
	notifier          storm.CIBANotificationCallback // optional, for ping delivery mode
	lifetime          time.Duration
	interval          time.Duration
	cibaTmpl          *template.Template
	csrfHandler       *httputil.CookieHandler
	skipTLSCertVerify bool
	allowPrivateIPs   bool
	endpointConfigs   shared.EndpointConfigMap // endpoint configurations (optional)
}

// Config holds the dependencies for the CIBA plugin.
type Config struct {
	// Store is the CIBA storage backend (required).
	Store storm.CIBAStore
	// ClientStore is the client storage (required).
	ClientStore storm.ClientStore
	// Lifetime is the auth_req_id expiration duration (default: 5m).
	// Override for testing with slow browser automation.
	Lifetime time.Duration
	// Interval is the minimum polling interval in seconds (default: 5).
	Interval time.Duration
	// CIBATemplate overrides the default CIBA approval page template.
	// The template receives a map with "AuthReqID", "ClientID", "Scope",
	// "BindingMessage", "UserCode", "Error", "CSRFToken" keys.
	// If nil, the embedded default template is used.
	CIBATemplate *template.Template
	// Notifier is an optional callback for CIBA ping delivery mode.
	// When set, the plugin calls OnCIBAStatusChange when a request is approved/denied.
	// If the storage also implements CIBANotificationCallback, this takes precedence.
	Notifier storm.CIBANotificationCallback
	// CSRFKey is a 32-byte key for signing CSRF cookies on the approval page.
	// If nil, CSRF protection is disabled (not recommended for production).
	CSRFKey []byte
}

// NewWithConfig creates a new CIBA plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	if cfg.Lifetime == 0 {
		cfg.Lifetime = 5 * time.Minute
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	p := &Plugin{
		store:       cfg.Store,
		clientStore: cfg.ClientStore,
		notifier:    cfg.Notifier,
		lifetime:    cfg.Lifetime,
		interval:    cfg.Interval,
		cibaTmpl:    cibaTmpl,
	}
	if cfg.CIBATemplate != nil {
		p.cibaTmpl = cfg.CIBATemplate
	}
	if len(cfg.CSRFKey) > 0 {
		p.csrfHandler = httputil.NewCookieHandler(cfg.CSRFKey, nil,
			httputil.WithPath("/ciba"),
			httputil.WithSameSite(http.SameSiteStrictMode),
			httputil.WithMaxAge(300),
		)
	}
	return p
}
