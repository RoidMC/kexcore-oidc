// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package rp

import (
	"context"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/client"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// VerifyTokens implement the Token Response Validation as defined in OIDC specification
// https://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation
func VerifyTokens[C protocol.IDClaims](ctx context.Context, accessToken, idToken string, v *IDTokenVerifier) (claims C, err error) {
	ctx, span := client.Tracer.Start(ctx, "VerifyTokens")
	defer span.End()

	var nilClaims C

	claims, err = VerifyIDToken[C](ctx, idToken, v)
	if err != nil {
		return nilClaims, err
	}
	if err := VerifyAccessToken(accessToken, claims.GetAccessTokenHash(), claims.GetSignatureAlgorithm()); err != nil {
		return nilClaims, err
	}
	return claims, nil
}

// VerifyIDToken validates the id token according to
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func VerifyIDToken[C protocol.IDClaims](ctx context.Context, token string, v *IDTokenVerifier) (claims C, err error) {
	ctx, span := client.Tracer.Start(ctx, "VerifyIDToken")
	defer span.End()

	var nilClaims C

	decrypted, err := protocol.DecryptToken(token)
	if err != nil {
		// If a decryption key is configured, try with that key.
		if v.DecryptionKey != nil {
			decrypted, err = protocol.DecryptTokenWithKey(token, v.DecryptionKey)
			if err != nil {
				return nilClaims, err
			}
		} else {
			return nilClaims, err
		}
	}
	payload, err := protocol.ParseToken(decrypted, &claims)
	if err != nil {
		return nilClaims, err
	}

	if err := protocol.CheckSubject(claims); err != nil {
		return nilClaims, err
	}

	if err = protocol.CheckIssuer(claims, v.Issuer); err != nil {
		return nilClaims, err
	}

	if err = protocol.CheckAudience(claims, v.ClientID); err != nil {
		return nilClaims, err
	}

	if err = protocol.CheckAZPVerifier(claims, v.AZP); err != nil {
		return nilClaims, err
	}

	if err = protocol.CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs, v.KeySet); err != nil {
		return nilClaims, err
	}

	if err = protocol.CheckExpiration(claims, v.Offset); err != nil {
		return nilClaims, err
	}

	if err = protocol.CheckIssuedAt(claims, v.MaxAgeIAT, v.Offset); err != nil {
		return nilClaims, err
	}

	if v.Nonce != nil {
		if err = protocol.CheckNonce(claims, v.Nonce(ctx)); err != nil {
			return nilClaims, err
		}
	}

	if err = protocol.CheckAuthorizationContextClassReference(claims, v.ACR); err != nil {
		return nilClaims, err
	}

	if err = protocol.CheckAuthTime(claims, v.MaxAge); err != nil {
		return nilClaims, err
	}

	return claims, nil
}

type IDTokenVerifier protocol.Verifier

// VerifyAccessToken validates the access token according to
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation
func VerifyAccessToken(accessToken, atHash string, sigAlgorithm string) error {
	if atHash == "" {
		return nil
	}

	actual, err := oidc.ClaimHash(accessToken, sigAlgorithm)
	if err != nil {
		return err
	}
	if actual != atHash {
		return protocol.ErrAtHash
	}
	return nil
}

// NewIDTokenVerifier returns a oidc.Verifier suitable for ID token verification.
func NewIDTokenVerifier(issuer, clientID string, keySet protocol.KeySet, options ...VerifierOption) *IDTokenVerifier {
	v := &IDTokenVerifier{
		Issuer:   issuer,
		ClientID: clientID,
		KeySet:   keySet,
		Offset:   time.Second,
		Nonce: func(_ context.Context) string {
			return ""
		},
		AZP: protocol.DefaultAZPVerifier(clientID),
	}

	for _, opts := range options {
		opts(v)
	}

	return v
}

// VerifierOption is the type for providing dynamic options to the IDTokenVerifier
type VerifierOption func(*IDTokenVerifier)

// WithIssuedAtOffset mitigates the risk of iat to be in the future
// because of clock skews with the ability to add an offset to the current time
func WithIssuedAtOffset(offset time.Duration) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.Offset = offset
	}
}

// WithIssuedAtMaxAge provides the ability to define the maximum duration between iat and now
func WithIssuedAtMaxAge(maxAge time.Duration) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.MaxAgeIAT = maxAge
	}
}

// WithNonce sets the function to check the nonce
func WithNonce(nonce func(context.Context) string) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.Nonce = nonce
	}
}

// WithACRVerifier sets the verifier for the acr claim
func WithACRVerifier(verifier protocol.ACRVerifier) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.ACR = verifier
	}
}

// WithAZPVerifier sets the verifier for the azp claim
func WithAZPVerifier(verifier protocol.AZPVerifier) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.AZP = verifier
	}
}

// WithAuthTimeMaxAge provides the ability to define the maximum duration between auth_time and now
func WithAuthTimeMaxAge(maxAge time.Duration) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.MaxAge = maxAge
	}
}

// WithSupportedSigningAlgorithms overwrites the default RS256 signing algorithm
func WithSupportedSigningAlgorithms(algs ...string) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.SupportedSignAlgs = algs
	}
}

// WithDecryptionKey sets a key for JWE decryption of encrypted ID tokens.
// If the ID token is JWE-encrypted and this key is provided, it will be used
// to decrypt the token before verifying the signature.
func WithDecryptionKey(key []byte) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.DecryptionKey = key
	}
}
