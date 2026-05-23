// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package oidc_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/roidmc/kexcore-oidc/v1/pkg/oidc"
)

func TestAuthRequest_LogValue(t *testing.T) {
	a := &oidc.AuthRequest{
		Scopes:       oidc.SpaceDelimitedArray{"a", "b"},
		ResponseType: "respType",
		ClientID:     "123",
		RedirectURI:  "http://example.com/callback",
	}
	want := slog.GroupValue(
		slog.Any("scopes", oidc.SpaceDelimitedArray{"a", "b"}),
		slog.String("response_type", "respType"),
		slog.String("client_id", "123"),
		slog.String("redirect_uri", "http://example.com/callback"),
	)
	got := a.LogValue()
	assert.Equal(t, want, got)
}
