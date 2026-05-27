// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op

import (
	"context"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
)

const (
	// DefaultPushedAuthRequestLifetime is the default lifetime of a pushed authorization
	// request URI in seconds. RFC 9126 recommends 600 seconds.
	DefaultPushedAuthRequestLifetime = 600 * time.Second
)

// PushedAuthRequestStorage is an optional interface that may be implemented by
// implementors of Storage to support Pushed Authorization Requests (PAR).
// https://datatracker.ietf.org/doc/html/rfc9126
type PushedAuthRequestStorage interface {
	// StorePushedAuthRequest stores the pushed authorization request parameters
	// and returns a request_uri that can be used to reference it.
	// The requestURI should be opaque and unique.
	// expiresIn is the lifetime of the request_uri in seconds (RFC 9126 recommends 600).
	StorePushedAuthRequest(ctx context.Context, clientID string, authReq *oidc.AuthRequest, expiresIn time.Duration) (requestURI string, err error)

	// PushedAuthRequestByURI retrieves the stored authorization request by its request_uri.
	// If the request_uri is expired or invalid, it should return an error.
	PushedAuthRequestByURI(ctx context.Context, clientID string, requestURI string) (*oidc.AuthRequest, error)
}
