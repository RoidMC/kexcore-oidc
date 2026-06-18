// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/roidmc/kexcore-oidc/example/storm-server/config"
	"github.com/roidmc/kexcore-oidc/example/storm-server/storage"

	// Import plugins for registration
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/authorization"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/backchannel"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/dcr"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/device"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/discovery"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/endsession"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/introspection"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/keys"
	_ "github.com/roidmc/kexcore-oidc/pkg/storm/plugins/mtls"
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

	// FAPI test key pairs for private_key_jwt (fixed, must match config.yml jwks)
	// Generated once, do NOT regenerate unless updating both main.go and config.yml
	fapiJWK1 := mustParseFAPIKey("-VA0fzoJpkWmuwRWilmc8xSrlrPVmAzlpMpQMiZetVc", "sWwU5hohNPTkEuyCeVYWySYuU9a-dPkBeoAApG8UTpk", "fapi-test-key-1")
	fapiJWK2 := mustParseFAPIKey("0YCniv9r1v7a95GbMZzxtz3w09clH7QhhKi65A2KvLw", "rG_x865khWLke14qOmogZlnSvJzvQ5yvxXdT0ySqjtw", "fapi-test-key-2")

	clients := []*storage.Client{
		storage.NativeClient("native", cfg.RedirectURI...),
		storage.WebClient("web", "secret", cfg.RedirectURI...),
		storage.WebClient("api", "secret", cfg.RedirectURI...),
		// Clients for rp-initiated-logout (no backchannel_logout_uri)
		storage.OIDFTestClientSecretPost("Test Client 1", "test-secret-1",
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		),
		storage.OIDFTestClientSecretPost("Test Client 2", "test-secret-2",
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		),
		// Clients for backchannel-rp-initiated-logout (with backchannel_logout_uri)
		storage.OIDFBackChannelLogoutTestClient("BCL Client 1", "bcl-secret-1",
			"https://192.168.2.167:8443/test/a/kexcore-test/backchannel_logout",
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		),
		storage.OIDFBackChannelLogoutTestClient("BCL Client 2", "bcl-secret-2",
			"https://192.168.2.167:8443/test/a/kexcore-test/backchannel_logout",
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
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
		// FAPI test clients — Security Profile (no request_object_signing_alg)
		storage.FAPIClient("FAPI Client 1", []jwk.Key{fapiJWK1},
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		).WithNotificationEndpoint("https://192.168.2.167:8443/test/a/kexcore-test/ciba-notification-endpoint"),
		storage.FAPIClient("FAPI Client 2", []jwk.Key{fapiJWK2},
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		).WithNotificationEndpoint("https://192.168.2.167:8443/test/a/kexcore-test/ciba-notification-endpoint"),
		// FAPI test clients — Message Signing (request_object_signing_alg = PS256)
		// Same JWK keys and mTLS certificates, but requires signed request objects.
		storage.FAPIClient("FAPI Client 1 MS", []jwk.Key{fapiJWK1},
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		).WithRequestObjectSigningAlg("PS256").WithNotificationEndpoint("https://192.168.2.167:8443/test/a/kexcore-test/ciba-notification-endpoint"),
		storage.FAPIClient("FAPI Client 2 MS", []jwk.Key{fapiJWK2},
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		).WithRequestObjectSigningAlg("PS256").WithNotificationEndpoint("https://192.168.2.167:8443/test/a/kexcore-test/ciba-notification-endpoint"),
		// FAPI test clients — mTLS (tls_client_auth, no client_assertion)
		// Used for CIBA mtls variants where client authenticates via TLS cert.
		// JWKS is still needed for request object signature verification.
		storage.FAPIClientMTLS("FAPI Client 1 MTLS", []jwk.Key{fapiJWK1},
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		).WithNotificationEndpoint("https://192.168.2.167:8443/test/a/kexcore-test/ciba-notification-endpoint").
			WithCertCN("FAPI Client 1"),
		storage.FAPIClientMTLS("FAPI Client 2 MTLS", []jwk.Key{fapiJWK2},
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		).WithNotificationEndpoint("https://192.168.2.167:8443/test/a/kexcore-test/ciba-notification-endpoint").
			WithCertCN("FAPI Client 2"),
		// FAPI test clients — mTLS auth + DPoP sender constraining only (requireDPoP=true, requireMtls=false)
		// Used for sender_constrain=dpop variants where the server must reject
		// requests without DPoP proof even when mTLS certificates are present.
		storage.FAPIClientMTLSDPoP("FAPI Client 1 MTLS DPoP", []jwk.Key{fapiJWK1},
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		).WithCertCN("FAPI Client 1"),
		storage.FAPIClientMTLSDPoP("FAPI Client 2 MTLS DPoP", []jwk.Key{fapiJWK2},
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		).WithCertCN("FAPI Client 2"),
		// FAPI test clients — Message Signing mTLS (tls_client_auth, request_object_signing_alg=PS256)
		storage.FAPIClientMTLS("FAPI Client 1 MS MTLS", []jwk.Key{fapiJWK1},
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		).WithRequestObjectSigningAlg("PS256").WithCertCN("FAPI Client 1"),
		storage.FAPIClientMTLS("FAPI Client 2 MS MTLS", []jwk.Key{fapiJWK2},
			"https://192.168.2.167:8443/test/a/kexcore-test/callback",
		).WithRequestObjectSigningAlg("PS256").WithCertCN("FAPI Client 2"),
	}

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
		Clients:           clients,
		AllowPrivateIPs:   config.EnableSelfSignSSL == "true",
		SkipTLSCertVerify: config.EnableSkipTLSCertVerify == "true",
		// DPoP/mTLS sender-constraining is configured per-client via DCR
		// (require_dpop / require_mtls fields) or static client builder methods.
	})

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				//tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				//tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				// ChaCha20-Poly1305 excluded: BCP 195 (RFC 9325) §4.2 only
				// recommends AES-GCM for TLS 1.2. FAPI 2.0 conformance tests
				// enforce this strictly. TLS 1.3 cipher suites are handled
				// automatically by Go's TLS stack and include ChaCha20.
			},
			// Enable mTLS: request client certificate but don't require it
			// (some tests use mTLS, others don't)
			ClientAuth: tls.RequestClientCert,
		},
	}

	logger.Info("storm-server listening", "addr", issuer, "tls", cfg.TLSCertFile != "")
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			logger.Error("server terminated", "error", err)
			os.Exit(1)
		}
	} else {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server terminated1", "error", err)
			os.Exit(1)
		}
	}
}

// mustParseFAPIKey returns a fixed JWK for FAPI private_key_jwt testing.
// The key must match the fapi_client.jwks in testsuite/config.yml.
func mustParseFAPIKey(xStr, yStr, kid string) jwk.Key {
	x, _ := base64.RawURLEncoding.DecodeString(xStr)
	y, _ := base64.RawURLEncoding.DecodeString(yStr)

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	key, _ := jwk.Import[jwk.Key](pub)
	key.Set(jwk.KeyIDKey, kid)
	key.Set(jwk.AlgorithmKey, "ES256")
	key.Set(jwk.KeyUsageKey, "sig")
	return key
}
