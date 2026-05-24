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

	"github.com/roidmc/kexcore-oidc/example/server/config"
	"github.com/roidmc/kexcore-oidc/example/server/exampleop"
	"github.com/roidmc/kexcore-oidc/example/server/storage"
)

func getUserStore(cfg *config.Config) (storage.UserStore, error) {
	if cfg.Issuer == "" {
		cfg.Issuer = fmt.Sprintf("http://localhost:%s/", cfg.Port)
	}
	if cfg.UsersFile == "" {
		return storage.NewUserStore(cfg.Issuer), nil
	}
	return storage.StoreFromFile(cfg.UsersFile)
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
		// OIDF Conformance Suite 测试客户端
		storage.WebClient("Test Client 1", "test-secret-1",
			"https://www.certification.openid.net/test/a/kexcore-test/callback",
		),
		storage.WebClient("Test Client 2", "test-secret-2",
			"https://www.certification.openid.net/test/a/kexcore-test/callback",
		),
	)

	// the OpenIDProvider interface needs a Storage interface handling various checks and state manipulations
	// this might be the layer for accessing your database
	// in this example it will be handled in-memory
	store, err := getUserStore(cfg)
	if err != nil {
		logger.Error("cannot create UserStore", "error", err)
		os.Exit(1)
	}

	stor := storage.NewStorageWithAlgorithms(store, cfg.SigningAlgorithms)
	router := exampleop.SetupServer(
		issuer,
		stor,
		logger,
		false,
		cfg.CryptoMethod,
		//op.WithCrypto(newMyCrypto(sha256.Sum256([]byte("test")), cfg.CryptoMethod, logger)),
	)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}
	logger.Info("server listening, press ctrl+c to stop", "addr", issuer)
	if server.ListenAndServe() != http.ErrServerClosed {
		logger.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
