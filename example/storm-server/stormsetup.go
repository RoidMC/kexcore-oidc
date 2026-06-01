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
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/example/storm-server/storage"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/plugins/authorization"
	"github.com/roidmc/kexcore-oidc/pkg/storm/plugins/endsession"
	"github.com/roidmc/kexcore-oidc/pkg/storm/plugins/introspection"
	"github.com/roidmc/kexcore-oidc/pkg/storm/plugins/keys"
	"github.com/roidmc/kexcore-oidc/pkg/storm/plugins/revocation"
	"github.com/roidmc/kexcore-oidc/pkg/storm/plugins/token"
	"github.com/roidmc/kexcore-oidc/pkg/storm/plugins/userinfo"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

var defaultDiscovery = storm.DiscoveryConfig{
	ExtraFields: map[string]any{
		"grant_types_supported": []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
		},
		"code_challenge_methods_supported": []string{"S256"},
	},
}

// TenantConfig configures a single OIDC tenant.
type TenantConfig struct {
	Issuer            string
	SigningAlgorithms []string
	CryptoMethod      string
	Logger            *slog.Logger
	Discovery         storm.DiscoveryConfig
	UserStore         storage.UserStore // optional, defaults to in-memory
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
		discovery = defaultDiscovery
	}

	userStore := cfg.UserStore
	if userStore == nil {
		userStore = storage.NewUserStore(cfg.Issuer)
	}
	stor := storage.NewStorage(userStore, cfg.SigningAlgorithms)
	tokenCrypto := storage.NewTokenCrypto(sha256.Sum256([]byte("test")), cfg.CryptoMethod)
	sharedKeyStore := storm.AdaptKeyStore(stor)

	decoder := protocol.NewDecoder()
	decoder.IgnoreUnknownKeys(true)

	engine := storm.New(stor, shared.StaticIssuer(cfg.Issuer),
		storm.WithLogger(cfg.Logger),
		storm.WithMiddleware(shared.IssuerMiddleware(shared.StaticIssuer(cfg.Issuer))),
		storm.WithDiscoveryConfig(discovery),
	)

	engine.Register(authorization.New(authorization.Config{
		AuthStore:   stor,
		ClientStore: stor,
		Crypto:      tokenCrypto,
		KeyStore:    stor,
		Decoder:     decoder,
	}))
	engine.Register(token.New(token.Config{
		TokenStore:  stor,
		ClientStore: stor,
		AuthStore:   stor,
		Crypto:      tokenCrypto,
		KeyStore:    stor,
		Decoder:     decoder,
		Logger:      cfg.Logger,
	}))
	engine.Register(introspection.New(introspection.Config{
		Store:       stor,
		ClientStore: stor,
		Crypto:      tokenCrypto,
		KeyStore:    sharedKeyStore,
	}))
	engine.Register(userinfo.New(userinfo.Config{
		Store:    stor,
		Crypto:   tokenCrypto,
		KeyStore: sharedKeyStore,
	}))
	engine.Register(revocation.New(revocation.Config{
		Store:       stor,
		ClientStore: stor,
		Crypto:      tokenCrypto,
		KeyStore:    sharedKeyStore,
	}))
	engine.Register(endsession.New(endsession.Config{
		Store:            stor,
		ClientStore:      stor,
		KeyStore:         sharedKeyStore,
		DefaultLogoutURI: "/",
	}))
	engine.Register(keys.New(stor))

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
		http.Redirect(w, r, issuer+"authorize/callback?id="+id, http.StatusFound)
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
<p><label>Username: <input name="username" value="test-user@localhost"></label></p>
<p><label>Password: <input name="password" type="password" value="verysecure"></label></p>
<p><button type="submit">Login</button></p>
</form>
</div>
</body></html>`))

func renderLogin(w http.ResponseWriter, id, issuer, errMsg string) {
	loginTmpl.Execute(w, map[string]string{
		"ID":     id,
		"Issuer": strings.TrimRight(issuer, "/"),
		"Error":  errMsg,
	})
}
