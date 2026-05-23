// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package oidc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

func TestFindKey(t *testing.T) {
	// Generate valid test keys (jwx v4 validates key sizes)
	testRSAKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	testECDSAKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	type args struct {
		keyID       string
		use         string
		expectedAlg string
		keys        []jwk.Key
	}
	type res struct {
		err error
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"no keys, ErrKeyNone",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys:        nil,
			},
			res{
				err: ErrKeyNone,
			},
		},
		{
			"single key enc, ErrKeyNone",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithUse(t, &testRSAKey.PublicKey, "enc"),
				},
			},
			res{
				err: ErrKeyNone,
			},
		},
		{
			"single key wrong algorithm, ErrKeyNone",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithType(t, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))),
				},
			},
			res{
				err: ErrKeyNone,
			},
		},
		{
			"single key no kid, no jwt kid, match",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithUse(t, &testRSAKey.PublicKey, "sig"),
				},
			},
			res{
				err: nil,
			},
		},
		{
			"single key kid, jwt no kid, match",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithKid(t, &testRSAKey.PublicKey, "id", "sig"),
				},
			},
			res{
				err: nil,
			},
		},
		{
			"single key no kid, jwt with kid, match",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithUse(t, &testRSAKey.PublicKey, "sig"),
				},
			},
			res{
				err: nil,
			},
		},
		{
			"single key no use, jwt with kid, match",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithKid(t, &testRSAKey.PublicKey, "id", ""),
				},
			},
			res{
				err: nil,
			},
		},
		{
			"single key wrong kid, ErrKeyNone",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithKid(t, &testRSAKey.PublicKey, "id2", "sig"),
				},
			},
			res{
				err: ErrKeyNone,
			},
		},
		{
			"multiple keys no kid, jwt no kid, ErrKeyMultiple",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithUse(t, &testRSAKey.PublicKey, "sig"),
					newKeyWithUse(t, &testRSAKey.PublicKey, "sig"),
				},
			},
			res{
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys with kid, jwt no kid, ErrKeyMultiple",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithKid(t, &testRSAKey.PublicKey, "id1", "sig"),
					newKeyWithKid(t, &testRSAKey.PublicKey, "id2", "sig"),
				},
			},
			res{
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys, single sig key, jwt no kid, match",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithUse(t, &testRSAKey.PublicKey, "sig"),
					newKeyWithUse(t, &testRSAKey.PublicKey, "enc"),
				},
			},
			res{
				err: nil,
			},
		},
		{
			"multiple keys no kid, jwt with kid, ErrKeyMultiple",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithUse(t, &testRSAKey.PublicKey, "sig"),
					newKeyWithUse(t, &testRSAKey.PublicKey, "sig"),
				},
			},
			res{
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys with kid, jwt with kid, match",
			args{
				keyID:       "id1",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithKid(t, &testRSAKey.PublicKey, "id1", "sig"),
					newKeyWithKid(t, &testRSAKey.PublicKey, "id2", "sig"),
				},
			},
			res{
				err: nil,
			},
		},
		{
			"multiple keys, single sig key, jwt with kid, match",
			args{
				keyID:       "id1",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithUse(t, &testRSAKey.PublicKey, "sig"),
					newKeyWithUse(t, &testRSAKey.PublicKey, "enc"),
				},
			},
			res{
				err: nil,
			},
		},
		{
			"multiple keys, no use, jwt with kid, match",
			args{
				keyID:       "id1",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithKid(t, &testRSAKey.PublicKey, "id1", ""),
					newKeyWithKid(t, &testRSAKey.PublicKey, "id2", ""),
				},
			},
			res{
				err: nil,
			},
		},
		{
			"multiple keys, no use, jwt without kid, ErrKeyMultiple",
			args{
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jwk.Key{
					newKeyWithKid(t, &testRSAKey.PublicKey, "id1", ""),
					newKeyWithKid(t, &testRSAKey.PublicKey, "id2", ""),
				},
			},
			res{
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys, no use or id, jwt with kid, ErrKeyMultiple",
			args{
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keyID:       "id1",
				keys: []jwk.Key{
					newKey(t, &testRSAKey.PublicKey),
					newKey(t, &testRSAKey.PublicKey),
				},
			},
			res{
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys (only one matching alg), jwt with kid, match",
			args{
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keyID:       "id1",
				keys: []jwk.Key{
					newKey(t, &testRSAKey.PublicKey),
					newKey(t, &testECDSAKey.PublicKey),
				},
			},
			res{
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindMatchingKey(tt.args.keyID, tt.args.use, tt.args.expectedAlg, tt.args.keys...)
			if (tt.res.err != nil && !errors.Is(err, tt.res.err)) || (tt.res.err == nil && err != nil) {
				t.Errorf("FindKey() error, got = %v, want = %v", err, tt.res.err)
			}
			if err != nil {
				return
			}

			// For matching results, verify the raw key type
			if tt.args.expectedAlg == "RS256" && len(tt.args.keys) > 0 {
				if got == nil {
					t.Errorf("FindMatchingKey() returned nil key for expected match")
					return
				}
			}
		})
	}
}

// newKey creates a jwk.Key from a raw key with no kid or use
func newKey(t *testing.T, rawKey interface{}) jwk.Key {
	t.Helper()
	key, err := jwk.Import[jwk.Key](rawKey)
	if err != nil {
		t.Fatalf("jwk.Import failed: %v", err)
	}
	return key
}

// newKeyWithKid creates a jwk.Key with a kid and optional use
func newKeyWithKid(t *testing.T, rawKey interface{}, kid, use string) jwk.Key {
	t.Helper()
	key, err := jwk.Import[jwk.Key](rawKey)
	if err != nil {
		t.Fatalf("jwk.Import failed: %v", err)
	}
	if kid != "" {
		if err := key.Set("kid", kid); err != nil {
			t.Fatalf("key.Set(kid) failed: %v", err)
		}
	}
	if use != "" {
		if err := key.Set("use", use); err != nil {
			t.Fatalf("key.Set(use) failed: %v", err)
		}
	}
	return key
}

// newKeyWithUse creates a jwk.Key with a use
func newKeyWithUse(t *testing.T, rawKey interface{}, use string) jwk.Key {
	t.Helper()
	key, err := jwk.Import[jwk.Key](rawKey)
	if err != nil {
		t.Fatalf("jwk.Import failed: %v", err)
	}
	if use != "" {
		if err := key.Set("use", use); err != nil {
			t.Fatalf("key.Set(use) failed: %v", err)
		}
	}
	return key
}

// newKeyWithType creates a jwk.Key with a specific raw key type
func newKeyWithType(t *testing.T, rawKey interface{}) jwk.Key {
	t.Helper()
	key, err := jwk.Import[jwk.Key](rawKey)
	if err != nil {
		t.Fatalf("jwk.Import failed: %v", err)
	}
	return key
}

// Ensure unused imports are not removed
var _ = rand.Reader
var _ = reflect.TypeOf
