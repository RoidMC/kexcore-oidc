// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op

import (
	"errors"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
)

var ErrSignerCreationFailed = errors.New("signer creation failed")

// SigningKey represents a key used for signing JWT tokens
type SigningKey interface {
	SignatureAlgorithm() string
	Key() any
	ID() string
}

// SM9SigningKey extends SigningKey with SM9-specific user identifier.
type SM9SigningKey interface {
	SigningKey
	SM9UID() []byte
}

// SignerFromKey creates a crypto.Signer from the signing key
func SignerFromKey(key SigningKey) (*crypto.Signer, error) {
	signer, err := crypto.NewSigner(key.SignatureAlgorithm(), key.Key(), key.ID())
	if err != nil {
		return nil, ErrSignerCreationFailed
	}
	if sm9Key, ok := key.(SM9SigningKey); ok && len(sm9Key.SM9UID()) > 0 {
		signer.SetSM9UID(sm9Key.SM9UID())
	}
	return signer, nil
}

// Key represents a key that is published in the JWKS endpoint
type Key interface {
	ID() string
	Algorithm() string
	Use() string
	Key() any
}
