// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/roidmc/kexcore-oidc/example/storm-server/config"
	"github.com/roidmc/kexcore-oidc/example/storm-server/storage"

	// Import plugins for registration
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/authorization"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/dcr"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/device"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/discovery"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/endsession"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/introspection"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/keys"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/revocation"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/token"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/userinfo"
)

func main() {
	cfg := config.FromEnvVars(&config.Config{Port: "9998"})
	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)

	issuer := cfg.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%s/", cfg.Port)
	}

	storage.RegisterClients(
		storage.NativeClient("native", cfg.RedirectURI...),
		storage.WebClient("web", "secret", cfg.RedirectURI...),
		storage.WebClient("api", "secret", cfg.RedirectURI...),
		storage.OIDFBackChannelLogoutTestClient("Test Client 1", "test-secret-1",
			"https://www.certification.openid.net/test/a/kexcore-test/backchannel_logout",
			"https://www.certification.openid.net/test/a/kexcore-test/callback",
		),
		storage.OIDFBackChannelLogoutTestClient("Test Client 2", "test-secret-2",
			"https://www.certification.openid.net/test/a/kexcore-test/backchannel_logout",
			"https://www.certification.openid.net/test/a/kexcore-test/callback",
		),
		storage.EncryptedWebClient("web-dir-sm4", "secret", "dir", "A256GCM",
			cfg.RedirectURI...,
		),
		storage.EncryptedWebClient("web-sm2", "secret", "SGD_SM2_3", "SGD_SM4_GCM",
			cfg.RedirectURI...,
		),
		storage.EncryptedWebClient("web-sm9", "secret", "SGD_SM9_3", "SGD_SM4_GCM",
			cfg.RedirectURI...,
		),
		storage.BackChannelLogoutWebClient("web-bcl", "secret", "http://localhost:9999/backchannel_logout",
			cfg.RedirectURI...,
		),
	)

	var userStore storage.UserStore
	if cfg.UsersFile != "" {
		us, err := storage.StoreFromFile(cfg.UsersFile)
		if err != nil {
			logger.Error("cannot load users file", "error", err)
			os.Exit(1)
		}
		userStore = us
	} else {
		userStore = storage.NewUserStore(issuer)
	}

	handler := SetupTenant(TenantConfig{
		Issuer:            issuer,
		SigningAlgorithms: cfg.SigningAlgorithms,
		CryptoMethod:      cfg.CryptoMethod,
		Logger:            logger,
		UserStore:         userStore,
	})

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
	}

	logger.Info("storm-server listening", "addr", issuer)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
