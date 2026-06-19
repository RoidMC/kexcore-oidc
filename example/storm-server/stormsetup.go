// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios
//
// stormsetup provides a one-call SetupTenant function for creating a complete
// Storm-based OIDC tenant. This is the Storm equivalent of example/server/exampleop.SetupServer.

package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/v2/example/storm-server/storage"
	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"

	// Import plugins to trigger init() self-registration.
	// Each plugin registers itself in the global registry.

	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/authorization"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/backchannel"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/ciba"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/device"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/discovery"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/dpop"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/endsession"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/introspection"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/jarm"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/keys"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/mtls"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/par"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/revocation"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/token"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/userinfo"
	_ "github.com/roidmc/kexcore-oidc/v2/pkg/storm/plugins/webfinger"
)

// defaultDiscoveryConfig builds the discovery configuration dynamically
// based on the signing algorithms and plugin capabilities.
// This mirrors the old OP's CreateDiscoveryConfig approach.
func defaultDiscoveryConfig(signingAlgorithms []string) storm.DiscoveryConfig {
	// All standard discovery fields are now contributed by plugins via Contribute().
	// ExtraFields is reserved for non-standard extension fields only.
	return storm.DiscoveryConfig{}
}

// TenantConfig configures a single OIDC tenant.
type TenantConfig struct {
	Issuer            string
	SigningAlgorithms []string
	CryptoMethod      string
	Logger            *slog.Logger
	Discovery         storm.DiscoveryConfig
	UserStore         storage.UserStore // optional, defaults to in-memory
	Clients           []*storage.Client // clients to register
	AllowPrivateIPs   bool              // WARNING: disables SSRF protection. Only for testing.
	SkipTLSCertVerify bool              // WARNING: disables TLS cert verification. Only for testing.
	RequireDPoP       bool              // FAPI 2.0: require DPoP proof for all token requests
	RequireMtls       bool              // FAPI 2.0: require mTLS client certificate for all token requests
}

// SetupTenant creates a complete OIDC tenant with all core plugins registered.
// Returns an http.Handler ready to be mounted on a router.
//
// Usage:
//
//	handler := SetupTenant(TenantConfig{
//	    Issuer:           "http://localhost:9998/",
//	    SigningAlgorithms: config.DefaultSigningAlgorithmsSlice(),
//	    Logger:           logger,
//	})
//	http.ListenAndServe(":9998", handler)
func SetupTenant(cfg TenantConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.CryptoMethod == "" {
		cfg.CryptoMethod = "aes"
	}
	if len(cfg.SigningAlgorithms) == 0 {
		// Default set covers all algorithms used by the bundled clients:
		// - RS256: OIDC Core default id_token_signed_response_alg
		// - PS256: FAPIClient default (FAPI 1.0/2.0 baseline)
		// - ES256/EdDSA: modern alternatives advertised in discovery
		cfg.SigningAlgorithms = []string{"RS256", "PS256", "ES256", "EdDSA"}
	}
	discovery := cfg.Discovery
	if discovery.ExtraFields == nil {
		discovery = defaultDiscoveryConfig(cfg.SigningAlgorithms)
	}

	userStore := cfg.UserStore
	if userStore == nil {
		userStore = storage.NewUserStore(cfg.Issuer)
	}
	stor := storage.NewStorage(userStore, cfg.SigningAlgorithms)

	// Register clients after storage creation
	if len(cfg.Clients) > 0 {
		stor.RegisterClients(cfg.Clients...)
	}

	tokenCrypto := storage.NewTokenCrypto(sha256.Sum256([]byte("test")), cfg.CryptoMethod)

	decoder := protocol.NewDecoder()

	// Plugins auto-register via init() — just create the engine.
	// The engine discovers all registered plugins, checks storage dependencies,
	// and registers them in priority order.
	engineOpts := []storm.EngineOption{
		storm.WithLogger(cfg.Logger),
		storm.WithMiddleware(shared.IssuerMiddleware(shared.StaticIssuer(cfg.Issuer))),
		storm.WithDiscoveryConfig(discovery),
		storm.WithCrypto(tokenCrypto),
		storm.WithDecoder(decoder),
		storm.WithImplicit(),
	}
	if cfg.AllowPrivateIPs {
		engineOpts = append(engineOpts, storm.WithAllowPrivateIPs())
	}
	if cfg.SkipTLSCertVerify {
		engineOpts = append(engineOpts, storm.WithSkipTLSCertVerify())
	}
	if cfg.RequireDPoP {
		engineOpts = append(engineOpts, storm.WithRequireDPoP())
	}
	if cfg.RequireMtls {
		engineOpts = append(engineOpts, storm.WithRequireMtls())
	}
	engine := storm.New(stor, shared.StaticIssuer(cfg.Issuer), engineOpts...)

	engineHandler := engine.Build()

	router := chi.NewRouter()
	router.Post("/admin/rotate-keys", func(w http.ResponseWriter, r *http.Request) {
		before := stor.SigningKeyCount()
		if err := stor.RotateSigningKey(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		after := stor.SigningKeyCount()
		slog.Default().Info("key rotation completed", "before", before, "after", after)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","keys_before":%d,"keys_after":%d}`, before, after)
	})
	router.Mount("/login/", http.StripPrefix("/login", loginHandler(stor, cfg.Issuer)))
	router.Mount("/", engineHandler)
	return router
}

func loginHandler(stor *storage.Storage, issuer string) http.Handler {
	r := chi.NewRouter()
	r.Get("/username", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("authRequestID")
		renderLogin(w, id, issuer, "", getClientUIInfo(stor, id))
	})
	r.Post("/username", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "cannot parse form", http.StatusBadRequest)
			return
		}
		id := r.FormValue("id")
		if err := stor.CheckUsernamePassword(r.FormValue("username"), r.FormValue("password"), id); err != nil {
			renderLogin(w, id, issuer, err.Error(), getClientUIInfo(stor, id))
			return
		}
		// Set session_id cookie after successful login
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    stor.GetAuthRequestSessionID(id),
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, strings.TrimRight(issuer, "/")+"/authorize/callback?id="+id, http.StatusFound)
	})
	r.Post("/cancel", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "cannot parse form", http.StatusBadRequest)
			return
		}
		id := r.FormValue("id")
		// Redirect to authorization callback with error.
		// The authorization plugin handles JARM-aware error responses.
		http.Redirect(w, r, strings.TrimRight(issuer, "/")+"/authorize/callback?id="+id+"&error=access_denied&error_description=user+denied+the+authorization+request", http.StatusFound)
	})
	return r
}

//go:embed template
var templateFS embed.FS

var loginTmpl = template.Must(template.ParseFS(templateFS, "template/login.html"))

type clientUIInfo struct {
	LogoURI   string
	PolicyURI string
	TOSURI    string
}

func getClientUIInfo(stor *storage.Storage, authRequestID string) clientUIInfo {
	if authRequestID == "" {
		return clientUIInfo{}
	}
	ar, err := stor.AuthRequestByID(context.Background(), authRequestID)
	if err != nil {
		return clientUIInfo{}
	}
	client, err := stor.GetClientByClientID(context.Background(), ar.GetClientID())
	if err != nil {
		return clientUIInfo{}
	}
	info := clientUIInfo{}
	type logoProvider interface {
		LogoURI() string
	}
	type policyProvider interface {
		PolicyURI() string
	}
	type tosProvider interface {
		TOSURI() string
	}
	if lp, ok := client.(logoProvider); ok {
		info.LogoURI = lp.LogoURI()
	}
	if pp, ok := client.(policyProvider); ok {
		info.PolicyURI = pp.PolicyURI()
	}
	if tp, ok := client.(tosProvider); ok {
		info.TOSURI = tp.TOSURI()
	}
	return info
}

func renderLogin(w http.ResponseWriter, id, issuer, errMsg string, uiInfo clientUIInfo) {
	trimmed := strings.TrimRight(issuer, "/")
	domain := trimmed
	if u, err := url.Parse(trimmed); err == nil && u.Host != "" {
		domain = u.Hostname()
	}
	loginTmpl.Execute(w, map[string]string{
		"ID":        id,
		"Issuer":    trimmed,
		"Domain":    domain,
		"Error":     errMsg,
		"LogoURI":   uiInfo.LogoURI,
		"PolicyURI": uiInfo.PolicyURI,
		"TOSURI":    uiInfo.TOSURI,
	})
}
