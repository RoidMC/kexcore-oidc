// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package rp

import (
	"context"
	"log/slog"

	"github.com/roidmc/kexcore-oidc/v2/pkg/util/logctx"
)

func logCtxWithRPData(ctx context.Context, rp RelyingParty, attrs ...any) context.Context {
	logger, ok := rp.Logger(ctx)
	if !ok {
		return ctx
	}
	logger = logger.With(slog.Group("rp", attrs...))
	return logctx.ToContext(ctx, logger)
}
