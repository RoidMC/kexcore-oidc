// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package oidc

import (
	"context"
	"errors"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const (
	KeyUseSignature = "sig"
)

var (
	ErrKeyMultiple = errors.New("multiple possible keys match")
	ErrKeyNone     = errors.New("no possible keys matches")
)

// KeySet represents a set of JSON Web Keys
// - remotely fetch via discovery and jwks_uri -> `remoteKeySet`
// - held by the OP itself in storage -> `openIDKeySet`
// - dynamically aggregated by request for OAuth JWT Profile Assertion -> `jwtProfileKeySet`
type KeySet interface {
	// VerifySignature verifies the signature with the given keyset and returns the raw payload
	VerifySignature(ctx context.Context, rawToken []byte) (payload []byte, err error)
}

// GetKeyIDAndAlg returns the `kid` and `alg` claim from the JWS header
func GetKeyIDAndAlg(jwsMsg *jws.Message) (string, string) {
	keyID := ""
	alg := ""
	for _, sig := range jwsMsg.Signatures() {
		keyID, _ = sig.ProtectedHeaders().KeyID()
		sigAlg, _ := sig.ProtectedHeaders().Algorithm()
		alg = sigAlg.String()
		break
	}
	return keyID, alg
}

// FindKey searches the given JSON Web Keys for the requested key ID, usage and key type
//
// will return the key immediately if matches exact (id, usage, type)
//
// will return false none or multiple match
//
// deprecated: use FindMatchingKey which will return an error (more specific) instead of just a bool
// moved implementation already to FindMatchingKey
func FindKey(keyID, use, expectedAlg string, keys ...jwk.Key) (jwk.Key, bool) {
	key, err := FindMatchingKey(keyID, use, expectedAlg, keys...)
	return key, err == nil
}

// FindMatchingKey searches the given JSON Web Keys for the requested key ID, usage and alg type
//
// will return the key immediately if matches exact (id, usage, type)
//
// will return a specific error if none (ErrKeyNone) or multiple (ErrKeyMultiple) match
func FindMatchingKey(keyID, use, expectedAlg string, keys ...jwk.Key) (key jwk.Key, err error) {
	var validKeys []jwk.Key
	for _, k := range keys {
		keyUsage, _ := k.KeyUsage()
		// ignore all keys with wrong use (let empty use of published key pass)
		if keyUsage != use && keyUsage != "" {
			continue
		}
		// ignore all keys with wrong algorithm type
		if !algToKeyType(k, expectedAlg) {
			continue
		}
		kid, _ := k.KeyID()
		// if we get here, use and alg match, so an equal (not empty) keyID is an exact match
		if kid == keyID && keyID != "" {
			return k, nil
		}
		// keyIDs did not match or at least one was empty (if later, then it could be a match)
		if kid == "" || keyID == "" {
			validKeys = append(validKeys, k)
		}
	}
	// if we get here, no match was possible at all (use / alg) or no exact match due to
	// the signed JWT and / or the published keys didn't have a kid
	// if later applies and only one key could be found, we'll return it
	// otherwise a corresponding error will be thrown
	if len(validKeys) == 1 {
		return validKeys[0], nil
	}
	if len(validKeys) > 1 {
		return nil, ErrKeyMultiple
	}
	return nil, ErrKeyNone
}

func algToKeyType(key jwk.Key, alg string) bool {
	kty := key.KeyType()
	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
		return kty == jwa.RSA()
	}
	if strings.HasPrefix(alg, "ES") {
		return kty == jwa.EC()
	}
	if alg == "EdDSA" {
		return kty == jwa.OKP()
	}
	return false
}
