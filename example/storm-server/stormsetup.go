// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios
//
// stormsetup provides a one-call SetupTenant function for creating a complete
// Storm-based OIDC tenant. This is the Storm equivalent of example/server/exampleop.SetupServer.

package main

import (
	"crypto/sha256"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/example/storm-server/storage"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"

	// Import plugins to trigger init() self-registration.
	// Each plugin registers itself in the global registry.

	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/authorization"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/backchannel"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/device"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/discovery"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/dpop"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/endsession"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/introspection"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/keys"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/mtls"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/par"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/revocation"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/token"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/userinfo"
)

// defaultGrantTypes returns the grant types supported by the default plugin set.
// Mirrors the old OP's GrantTypes() logic.
func defaultGrantTypes() []string {
	return []string{
		"authorization_code",
		"client_credentials",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:token-exchange",
		"urn:ietf:params:oauth:grant-type:device_code",
	}
}

// defaultResponseTypes returns the response types supported by the default plugin set.
// Mirrors the old OP's ResponseTypes() logic.
func defaultResponseTypes() []string {
	return []string{
		"code",
		"id_token",
		"id_token token",
		"code id_token",
		"code token",
		"code id_token token",
	}
}

// defaultAuthMethodsTokenEndpoint returns the token endpoint auth methods.
// Mirrors the old OP's AuthMethodsTokenEndpoint() logic.
func defaultAuthMethodsTokenEndpoint() []string {
	return []string{
		"none",
		"client_secret_basic",
		"client_secret_post",
		"private_key_jwt",
	}
}

// defaultDiscoveryConfig builds the discovery configuration dynamically
// based on the signing algorithms and plugin capabilities.
// This mirrors the old OP's CreateDiscoveryConfig approach.
func defaultDiscoveryConfig(signingAlgorithms []string) storm.DiscoveryConfig {
	return storm.DiscoveryConfig{
		ExtraFields: map[string]any{
			"grant_types_supported":                            defaultGrantTypes(),
			"response_types_supported":                         defaultResponseTypes(),
			"token_endpoint_auth_methods_supported":            defaultAuthMethodsTokenEndpoint(),
			"code_challenge_methods_supported":                 []string{"S256"},
			"scopes_supported":                                 []string{"openid", "profile", "email", "phone", "address", "offline_access"},
			"claims_supported":                                 []string{"sub", "aud", "exp", "iat", "iss", "auth_time", "nonce", "acr", "amr", "c_hash", "at_hash", "name", "given_name", "family_name", "preferred_username", "email", "email_verified", "phone_number", "phone_number_verified", "locale"},
			"subject_types_supported":                          []string{"public", "pairwise"},
			"id_token_signing_alg_values_supported":            signingAlgorithms,
			"token_endpoint_auth_signing_alg_values_supported": signingAlgorithms,
			"introspection_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},
			"revocation_endpoint_auth_methods_supported":       []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},
		},
	}
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
		cfg.SigningAlgorithms = []string{"RS256", "EdDSA"}
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
	decoder.IgnoreUnknownKeys(true)

	// Plugins auto-register via init() — just create the engine.
	// The engine discovers all registered plugins, checks storage dependencies,
	// and registers them in priority order.
	engine := storm.New(stor, shared.StaticIssuer(cfg.Issuer),
		storm.WithLogger(cfg.Logger),
		storm.WithMiddleware(shared.IssuerMiddleware(shared.StaticIssuer(cfg.Issuer))),
		storm.WithDiscoveryConfig(discovery),
		storm.WithCrypto(tokenCrypto),
		storm.WithDecoder(decoder),
		storm.WithImplicit(),
	)

	engineHandler := engine.Build()

	router := chi.NewRouter()
	router.Mount("/login/", http.StripPrefix("/login", loginHandler(stor, cfg.Issuer)))
	router.Mount("/", engineHandler)
	return router
}

func loginHandler(stor *storage.Storage, issuer string) http.Handler {
	r := chi.NewRouter()
	r.Get("/username", func(w http.ResponseWriter, r *http.Request) {
		renderLogin(w, r.URL.Query().Get("authRequestID"), issuer, "")
	})
	r.Post("/username", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "cannot parse form", http.StatusBadRequest)
			return
		}
		id := r.FormValue("id")
		if err := stor.CheckUsernamePassword(r.FormValue("username"), r.FormValue("password"), id); err != nil {
			renderLogin(w, id, issuer, err.Error())
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
	return r
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html><head><title>Login — {{.Issuer}}</title></head>
<body style="display:flex;align-items:center;justify-content:center;height:100vh">
<div>
<h2>{{.Issuer}}</h2>
{{if .Error}}<p style="color:red">{{.Error}}</p>{{end}}
<form method="POST" action="/login/username">
<input type="hidden" name="id" value="{{.ID}}">
<p><label>Username: <input name="username" value="test-user@{{.Domain}}"></label></p>
<p><label>Password: <input name="password" type="password" value="verysecure"></label></p>
<p><button type="submit">Login</button></p>
</form>
</div>
</body></html>`))

func renderLogin(w http.ResponseWriter, id, issuer, errMsg string) {
	trimmed := strings.TrimRight(issuer, "/")
	domain := trimmed
	if u, err := url.Parse(trimmed); err == nil && u.Host != "" {
		domain = u.Hostname()
	}
	loginTmpl.Execute(w, map[string]string{
		"ID":     id,
		"Issuer": trimmed,
		"Domain": domain,
		"Error":  errMsg,
	})
}
