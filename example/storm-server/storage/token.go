// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package storage

import (
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type Token struct {
	ID             string
	ApplicationID  string
	Subject        string
	RefreshTokenID string
	Audience       []string
	Expiration     time.Time
	Scopes         []string
	Claims         *protocol.ClaimsRequest
	CNF            map[string]any
}

type RefreshToken struct {
	ID            string
	Token         string
	AuthTime      time.Time
	AMR           []string
	Audience      []string
	UserID        string
	ApplicationID string
	Expiration    time.Time
	Scopes        []string
	AccessToken   string
	SessionID     string
	// DPoPJKT stores the JWK thumbprint bound to this refresh token.
	// Inherited from the associated access token's cnf.jkt when the token
	// is DPoP-bound (RFC 9449 §7.2).
	DPoPJKT string
}
