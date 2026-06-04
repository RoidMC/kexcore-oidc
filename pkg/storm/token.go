// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storm

import (
	"context"
	"strings"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
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

	// Standard opaque token decryption
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
