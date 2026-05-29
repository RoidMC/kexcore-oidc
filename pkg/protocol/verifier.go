package protocol

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
)

type AccessTokenVerifier struct {
	Issuer   string
	KeyStore KeyStore
	Offset   time.Duration
}

type IDTokenHintVerifier struct {
	Issuer    string
	KeyStore  KeyStore
	Offset    time.Duration
	MaxAgeIAT time.Duration
	MaxAge    time.Duration
}

type IDTokenHintExpiredError struct {
	Err error
}

func (e *IDTokenHintExpiredError) Error() string { return e.Err.Error() }
func (e *IDTokenHintExpiredError) Unwrap() error { return e.Err }

var ErrInvalidRefreshToken = errors.New("invalid refresh token")

func VerifyAccessToken(ctx context.Context, token string, v *AccessTokenVerifier) (tokenID, subject string, ok bool) {
	decrypted, err := oidc.DecryptToken(token)
	if err != nil {
		return "", "", false
	}

	claims := new(oidc.AccessTokenClaims)
	payload, err := oidc.ParseToken(decrypted, claims)
	if err != nil {
		return "", "", false
	}

	if err := oidc.CheckIssuer(claims, v.Issuer); err != nil {
		return "", "", false
	}

	keySet := &keyStoreAdapter{store: v.KeyStore}
	if err := oidc.CheckSignature(ctx, decrypted, payload, claims, nil, keySet); err != nil {
		return "", "", false
	}

	if err := oidc.CheckExpiration(claims, v.Offset); err != nil {
		return "", "", false
	}

	return claims.JWTID, claims.GetSubject(), true
}

func VerifyIDTokenHint(ctx context.Context, token string, v *IDTokenHintVerifier) (*oidc.IDTokenClaims, error) {
	decrypted, err := oidc.DecryptToken(token)
	if err != nil {
		return nil, err
	}

	claims := new(oidc.IDTokenClaims)
	payload, err := oidc.ParseToken(decrypted, claims)
	if err != nil {
		return nil, err
	}

	if err := oidc.CheckIssuer(claims, v.Issuer); err != nil {
		return nil, err
	}

	keySet := &keyStoreAdapter{store: v.KeyStore}
	if err := oidc.CheckSignature(ctx, decrypted, payload, claims, nil, keySet); err != nil {
		return nil, err
	}

	if err := oidc.CheckExpiration(claims, v.Offset); err != nil {
		return claims, &IDTokenHintExpiredError{Err: err}
	}

	if err := oidc.CheckIssuedAt(claims, v.MaxAgeIAT, v.Offset); err != nil {
		return claims, &IDTokenHintExpiredError{Err: err}
	}

	if err := oidc.CheckAuthTime(claims, v.MaxAge); err != nil {
		return claims, &IDTokenHintExpiredError{Err: err}
	}

	return claims, nil
}

func VerifyJWTAssertion(ctx context.Context, assertion string, issuer string, ks KeyStore, offset time.Duration) (*oidc.JWTTokenRequest, error) {
	request := new(oidc.JWTTokenRequest)
	payload, err := oidc.ParseToken(assertion, request)
	if err != nil {
		return nil, err
	}

	if err := oidc.CheckAudience(request, issuer); err != nil {
		return nil, err
	}

	if err := oidc.CheckExpiration(request, offset); err != nil {
		return nil, err
	}

	if request.Issuer != request.Subject {
		return nil, oidc.ErrSubjectInvalid
	}

	keySet := &keyStoreAdapter{store: ks}
	if err := oidc.CheckSignature(ctx, assertion, payload, request, nil, keySet); err != nil {
		return nil, err
	}

	return request, nil
}

type keyStoreAdapter struct {
	store KeyStore
}

func (a *keyStoreAdapter) VerifySignature(ctx context.Context, rawToken []byte) ([]byte, error) {
	keys, err := a.store.KeySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching keys: %w", err)
	}

	jwsMsg, err := jws.Parse(rawToken)
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	keyID, alg := oidc.GetKeyIDAndAlg(jwsMsg)

	var jwkKeys []jwk.Key
	for _, k := range keys {
		jk := k.Key()
		if id := k.ID(); id != "" {
			_ = jk.Set(jwk.KeyIDKey, id)
		}
		if use := k.Use(); use != "" {
			_ = jk.Set(jwk.KeyUsageKey, use)
		}
		jwkKeys = append(jwkKeys, jk)
	}

	key, err := oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, jwkKeys...)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	return VerifySignature(ctx, jwsMsg, rawToken, key, alg)
}
