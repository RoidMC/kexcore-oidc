// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storm

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

// GMDecryptor is an optional interface for GM/T JWE decryption.
// Implementations that support GM/T can implement this interface.
type GMDecryptor interface {
	SM2DecryptJWE(ctx context.Context, compact string) ([]byte, error)
}

// ResolveToken resolves an opaque token to its tokenID and subject.
// Supports standard decrypted tokens, GM/T JWE tokens, and JWT access tokens.
//
// This is the shared implementation used by both introspection and userinfo plugins.
func ResolveToken(ctx context.Context, crypto UniCrypto, keyStore protocol.KeyStore, issuer, token string) (tokenID, subject string, ok bool) {
	var plaintext []byte
	var err error

	// Try GM/T JWE decryption first (SM2+SM4-GCM per GM/T 0125.3)
	if gm, ok := crypto.(GMDecryptor); ok {
		plaintext, err = gm.SM2DecryptJWE(ctx, token)
		if err == nil {
			return ParseTokenParts(plaintext)
		}
	}

	// Standard opaque token decryption.
	// Tokens are base64-encoded ciphertext, but also try raw bytes
	// for backward compatibility with tokens issued before base64 encoding.
	if raw, decErr := base64.RawURLEncoding.DecodeString(token); decErr == nil {
		plaintext, err = crypto.Decrypt(ctx, raw)
		if err == nil {
			return ParseTokenParts(plaintext)
		}
	}
	// Fallback: try raw bytes (for tokens issued before base64 encoding)
	plaintext, err = crypto.Decrypt(ctx, []byte(token))
	if err == nil {
		return ParseTokenParts(plaintext)
	}

	// Opaque decryption failed - try JWT access token verification (RFC 6750 §2.1)
	if keyStore != nil {
		v := &protocol.AccessTokenVerifier{
			Issuer:   issuer,
			KeyStore: keyStore,
		}
		return protocol.VerifyAccessToken(ctx, token, v)
	}

	return "", "", false
}

// ParseTokenParts splits "tokenID:subject" plaintext into its components.
func ParseTokenParts(plaintext []byte) (tokenID, subject string, ok bool) {
	parts := strings.SplitN(string(plaintext), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// NewClientAuthHelper creates a shared.ClientAuthHelper from a storm.ClientStore.
// This bridges the type gap between storm.Client (superset with LoginURL)
// and shared.Client (minimal interface) that Go's type system doesn't allow
// via covariant return types.
func NewClientAuthHelper(cs ClientStore) *shared.ClientAuthHelper {
	return shared.NewClientAuthHelperFromFuncs(
		func(ctx context.Context, clientID string) (shared.Client, error) {
			return cs.GetClientByClientID(ctx, clientID)
		},
		cs.AuthorizeClientIDSecret,
	)
}
