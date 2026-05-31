package op

import (
	"context"
	"errors"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type IDTokenHintVerifier protocol.Verifier

type IDTokenHintVerifierOpt func(*IDTokenHintVerifier)

func WithSupportedIDTokenHintSigningAlgorithms(algs ...string) IDTokenHintVerifierOpt {
	return func(verifier *IDTokenHintVerifier) {
		verifier.SupportedSignAlgs = algs
	}
}

func NewIDTokenHintVerifier(issuer string, keySet protocol.KeySet, opts ...IDTokenHintVerifierOpt) *IDTokenHintVerifier {
	verifier := &IDTokenHintVerifier{
		Issuer: issuer,
		KeySet: keySet,
	}
	for _, opt := range opts {
		opt(verifier)
	}
	return verifier
}

type IDTokenHintExpiredError struct {
	error
}

func (e IDTokenHintExpiredError) Unwrap() error {
	return e.error
}

func (e IDTokenHintExpiredError) Is(err error) bool {
	return errors.Is(err, e.error)
}

// VerifyIDTokenHint validates the id token according to
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation.
// In case of an expired token both the Claims and first encountered expiry related error
// is returned of type [IDTokenHintExpiredError]. In that case the caller can choose to still
// trust the token for cases like logout, as signature and other verifications succeeded.
func VerifyIDTokenHint[C protocol.Claims](ctx context.Context, token string, v *IDTokenHintVerifier) (claims C, err error) {
	ctx, span := Tracer.Start(ctx, "VerifyIDTokenHint")
	defer span.End()

	var nilClaims C

	decrypted, err := protocol.DecryptToken(token)
	if err != nil {
		return nilClaims, err
	}
	payload, err := protocol.ParseToken(decrypted, &claims)
	if err != nil {
		return nilClaims, err
	}

	if err := protocol.CheckIssuer(claims, v.Issuer); err != nil {
		return nilClaims, err
	}

	if err = protocol.CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs, v.KeySet); err != nil {
		return nilClaims, err
	}

	if err = protocol.CheckAuthorizationContextClassReference(claims, v.ACR); err != nil {
		return nilClaims, err
	}

	if err = protocol.CheckExpiration(claims, v.Offset); err != nil {
		return claims, IDTokenHintExpiredError{err}
	}

	if err = protocol.CheckIssuedAt(claims, v.MaxAgeIAT, v.Offset); err != nil {
		return claims, IDTokenHintExpiredError{err}
	}

	if err = protocol.CheckAuthTime(claims, v.MaxAge); err != nil {
		return claims, IDTokenHintExpiredError{err}
	}
	return claims, nil
}
