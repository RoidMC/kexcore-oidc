// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"

	"github.com/emmansun/gmsm/sm3"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

const (
	SM2 = "SM2"
)

var ErrUnsupportedAlgorithm = errors.New("unsupported signing algorithm")

func GetHashAlgorithm(sigAlgorithm string) (hash.Hash, error) {
	switch sigAlgorithm {
	case jwa.RS256().String(), jwa.ES256().String(), jwa.PS256().String(), jwa.HS256().String():
		return sha256.New(), nil
	case jwa.RS384().String(), jwa.ES384().String(), jwa.PS384().String(), jwa.HS384().String():
		return sha512.New384(), nil
	case jwa.RS512().String(), jwa.ES512().String(), jwa.PS512().String(), jwa.HS512().String():
		return sha512.New(), nil

	// There is no published spec for this yet, but we have confirmation it will get published.
	// There is consensus here: https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens
	// Currently Go only supports the ed25519 curve key for EdDSA, so we can safely assume sha512 here.
	// It is unlikely ed448 will ever be supported: https://github.com/golang/go/issues/29390
	case jwa.EdDSA().String():
		return sha512.New(), nil

	case SM2:
		return sm3.New(), nil

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, sigAlgorithm)
	}
}

func HashString(hash hash.Hash, s string, firstHalf bool) string {
	if hash == nil {
		return s
	}
	//nolint:errcheck
	hash.Write([]byte(s))
	size := hash.Size()
	if firstHalf {
		size = size / 2
	}
	sum := hash.Sum(nil)[:size]
	return base64.RawURLEncoding.EncodeToString(sum)
}
