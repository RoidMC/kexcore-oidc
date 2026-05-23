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
	// GM/T 0125.1-2022 algorithm identifiers
	SGD_SM3_SM2  = "SGD_SM3_SM2"  // SM2+SM3 digital signature
	SGD_SM3_SM9  = "SGD_SM3_SM9"  // SM9+SM3 digital signature (identity-based)
	SGD_SM3_HMAC = "SGD_SM3_HMAC" // SM3 keyed-HMAC
	SGD_SM2_3    = "SGD_SM2_3"    // SM2 public key encryption (JWE key wrapping)
	SGD_SM9_3    = "SGD_SM9_3"    // SM9 encryption (JWE key wrapping)
	SGD_SM4_CCM  = "SGD_SM4_CCM"  // SM4 in CCM mode (JWE content encryption)
	SGD_SM4_GCM  = "SGD_SM4_GCM"  // SM4 in GCM mode (JWE content encryption)
)

var ErrUnsupportedAlgorithm = errors.New("unsupported signing algorithm")

func init() {
	// Register GM/T custom algorithms with jwx so that jws.Parse and jwe.Parse
	// can recognize SGD_SM3_SM2, SGD_SM3_SM9, SGD_SM9_3, SGD_SM4_GCM, etc.
	jwa.RegisterSignatureAlgorithm(
		jwa.NewSignatureAlgorithm(SGD_SM3_SM2),
		jwa.NewSignatureAlgorithm(SGD_SM3_SM9),
	)
	jwa.RegisterKeyEncryptionAlgorithm(
		jwa.NewKeyEncryptionAlgorithm(SGD_SM2_3),
		jwa.NewKeyEncryptionAlgorithm(SGD_SM9_3),
	)
	jwa.RegisterContentEncryptionAlgorithm(
		jwa.NewContentEncryptionAlgorithm(SGD_SM4_GCM),
		jwa.NewContentEncryptionAlgorithm(SGD_SM4_CCM),
	)
}

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

	case SGD_SM3_SM2, SGD_SM3_SM9:
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
