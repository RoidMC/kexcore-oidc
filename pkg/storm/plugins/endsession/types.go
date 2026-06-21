package endsession

import (
	"context"
	_ "embed"
	"html/template"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

//go:embed template/logout.html.tmpl
var logoutHtmlTemplate string

var logoutTmpl = template.Must(template.New("logout").Parse(logoutHtmlTemplate))

// LogoutHook is called after a session is terminated.
// Implementations can use this to trigger back-channel logout,
// audit logging, or other post-logout actions.
type LogoutHook interface {
	PostLogout(ctx context.Context, userID, clientID, sid string)
}

// LogoutHookFunc is a convenience adapter for LogoutHook.
type LogoutHookFunc func(ctx context.Context, userID, clientID, sid string)

func (f LogoutHookFunc) PostLogout(ctx context.Context, userID, clientID, sid string) {
	f(ctx, userID, clientID, sid)
}

// Plugin implements the OIDC End Session endpoint.
type Plugin struct {
	store            storm.SessionStore
	clientStore      storm.ClientStore
	keyStore         protocol.KeyStore
	defaultLogoutURI string
	offset           time.Duration
	maxAgeIAT        time.Duration
	maxAge           time.Duration
	decoder          *protocol.Decoder
	logoutHook       LogoutHook
	logoutTmpl       *template.Template
	endpointConfigs  shared.EndpointConfigMap // endpoint configurations (optional)
}

// Config holds the dependencies for the EndSession plugin.
type Config struct {
	Store            storm.SessionStore
	ClientStore      storm.ClientStore
	KeyStore         protocol.KeyStore
	DefaultLogoutURI string
	// Offset is the clock skew tolerance for token validation (default: 0).
	Offset time.Duration
	// MaxAgeIAT is the maximum allowed age of the id_token_hint's iat claim.
	// Per OIDC Session Management §5, expired tokens can still be trusted for logout.
	// Set to 0 to disable iat_max_age checking.
	MaxAgeIAT time.Duration
	// MaxAge is the maximum allowed time since auth_time.
	// Set to 0 to disable auth_time max_age checking.
	MaxAge  time.Duration
	Decoder *protocol.Decoder
	// LogoutHook is called after a session is terminated.
	// Use this to trigger back-channel logout, audit logging, etc.
	LogoutHook LogoutHook
	// LogoutTemplate overrides the default logout HTML template.
	// The template receives a map with "Title", "Heading", and "Message" keys.
	// If nil, the embedded default template is used.
	LogoutTemplate *template.Template
}

// New creates a new EndSession plugin from a PluginContext.
func New(ctx *storm.PluginContext) *Plugin {
	return &Plugin{
		store:            ctx.Storage.(storm.SessionStore),
		clientStore:      ctx.Storage.(storm.ClientStore),
		keyStore:         ctx.Storage.(storm.KeyStore),
		defaultLogoutURI: "/",
		decoder:          ctx.Decoder,
		logoutTmpl:       logoutTmpl,
		endpointConfigs:  ctx.EndpointConfigs,
	}
}

// NewWithConfig creates a new EndSession plugin with explicit config.
func NewWithConfig(cfg Config) *Plugin {
	p := &Plugin{
		store:            cfg.Store,
		clientStore:      cfg.ClientStore,
		keyStore:         cfg.KeyStore,
		defaultLogoutURI: cfg.DefaultLogoutURI,
		offset:           cfg.Offset,
		maxAgeIAT:        cfg.MaxAgeIAT,
		maxAge:           cfg.MaxAge,
		decoder:          cfg.Decoder,
		logoutHook:       cfg.LogoutHook,
		logoutTmpl:       logoutTmpl,
	}
	if cfg.LogoutTemplate != nil {
		p.logoutTmpl = cfg.LogoutTemplate
	}
	return p
}

// SetLogoutHook sets the logout hook for post-logout actions.
// This is used by Engine to auto-connect BackChannel plugin.
func (p *Plugin) SetLogoutHook(hook interface{}) {
	if lh, ok := hook.(LogoutHook); ok {
		p.logoutHook = lh
	}
}
