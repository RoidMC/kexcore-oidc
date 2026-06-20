// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package main

import (
	"log/slog"
	"net/http"

	"github.com/roidmc/kexcore-oidc/v2/example/storm-server/stormsetup"
)

// TenantConfig re-exports the stormsetup.TenantConfig for use in main.
type TenantConfig = stormsetup.TenantConfig

// SetupTenant re-exports the stormsetup.SetupTenant for use in main.
func SetupTenant(cfg TenantConfig) http.Handler {
	return stormsetup.SetupTenant(cfg)
}

// setupTenantForMain creates a tenant using the default storage and config.
func setupTenantForMain(issuer string, logger *slog.Logger) http.Handler {
	return stormsetup.SetupTenant(stormsetup.TenantConfig{
		Issuer: issuer,
		Logger: logger,
	})
}
