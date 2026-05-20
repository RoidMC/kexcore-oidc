// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"

	"github.com/go-jose/go-jose/v4"

	gmsm "github.com/emmansun/gmsm/sm2"
)

var (
	ErrPEMDecode             = errors.New("PEM decode failed")
	ErrUnsupportedFormat     = errors.New("key is neither in PKCS#1 nor PKCS#8 format")
	ErrUnsupportedPrivateKey = errors.New("unsupported key type, must be RSA, ECDSA, ED25519 or SM2 private key")
)

var oidSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}

type pkcs8Key struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func BytesToPrivateKey(b []byte) (crypto.PublicKey, jose.SignatureAlgorithm, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, "", ErrPEMDecode
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, jose.RS256, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		switch privateKey := key.(type) {
		case *rsa.PrivateKey:
			return privateKey, jose.RS256, nil
		case ed25519.PrivateKey:
			return privateKey, jose.EdDSA, nil
		case *ecdsa.PrivateKey:
			return privateKey, jose.ES256, nil
		default:
			return nil, "", ErrUnsupportedPrivateKey
		}
	}

	var pkcs8 pkcs8Key
	if _, restErr := asn1.Unmarshal(block.Bytes, &pkcs8); restErr == nil {
		if pkcs8.Algo.Algorithm.Equal(oidSM2) {
			var ecKey ecPrivateKey
			if _, restErr := asn1.Unmarshal(pkcs8.PrivateKey, &ecKey); restErr == nil {
				sm2Key, err := gmsm.NewPrivateKey(ecKey.PrivateKey)
				if err != nil {
					return nil, "", ErrUnsupportedFormat
				}
				return sm2Key, SM2, nil
			}
		}
	}

	return nil, "", ErrUnsupportedFormat
}
