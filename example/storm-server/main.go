// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package main

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/roidmc/kexcore-oidc/example/storm-server/config"
	"github.com/roidmc/kexcore-oidc/example/storm-server/storage"
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

// OAuth 2.1 + OIDC Core compliant discovery configuration.
var oauth21Discovery = storm.DiscoveryConfig{
	ExtraFields: map[string]any{
		"grant_types_supported": []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"urn:ietf:params:oauth:grant-type:device_code",
		},
		"response_types_supported": []string{
			"code",
			"id_token",
			"id_token token",
			"code id_token",
			"code token",
			"code id_token token",
		},
		"code_challenge_methods_supported": []string{"S256"},
	},
}

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

	store, err := getUserStore(cfg, issuer)
	if err != nil {
		logger.Error("cannot create UserStore", "error", err)
		os.Exit(1)
	}

	stor := storage.NewStorage(store, cfg.SigningAlgorithms)
	tokenCrypto := storage.NewTokenCrypto(sha256.Sum256([]byte("test")), cfg.CryptoMethod)
	sharedKeyStore := storm.AdaptKeyStore(stor)

	// Create StormEngine
	engine := storm.New(stor, shared.StaticIssuer(issuer),
		storm.WithLogger(logger),
		storm.WithMiddleware(shared.IssuerMiddleware(shared.StaticIssuer(issuer))),
		storm.WithDiscoveryConfig(oauth21Discovery),
	)

	// Register Authorization plugin
	engine.Register(authorization.New(authorization.Config{
		AuthStore:   stor,
		ClientStore: stor,
		Crypto:      tokenCrypto,
		KeyStore:    stor,
	}))

	// Register Token plugin
	engine.Register(token.New(token.Config{
		TokenStore:  stor,
		ClientStore: stor,
		AuthStore:   stor,
		Crypto:      tokenCrypto,
		KeyStore:    stor,
		Logger:      logger,
	}))

	// Register Introspection plugin
	engine.Register(introspection.New(introspection.Config{
		Store:       stor,
		ClientStore: stor,
		Crypto:      tokenCrypto,
		KeyStore:    sharedKeyStore,
	}))

	// Register UserInfo plugin
	engine.Register(userinfo.New(userinfo.Config{
		Store:    stor,
		Crypto:   tokenCrypto,
		KeyStore: sharedKeyStore,
	}))

	// Register Revocation plugin
	engine.Register(revocation.New(revocation.Config{
		Store:       stor,
		ClientStore: stor,
		Crypto:      tokenCrypto,
		KeyStore:    sharedKeyStore,
	}))

	// Register EndSession plugin
	engine.Register(endsession.New(endsession.Config{
		Store:            stor,
		ClientStore:      stor,
		KeyStore:         sharedKeyStore,
		DefaultLogoutURI: "/",
	}))

	// Register Keys (JWKS) plugin
	engine.Register(keys.New(stor))

	// Build and serve
	handler := engine.Build()

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

func getUserStore(cfg *config.Config, issuer string) (storage.UserStore, error) {
	if cfg.UsersFile == "" {
		return storage.NewUserStore(issuer), nil
	}
	return storage.StoreFromFile(cfg.UsersFile)
}
