// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/roidmc/kexcore-oidc/v1/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/v1/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/v1/pkg/op"
)

// --- Helpers for building GM/T JWS tokens ---

// sm2SignToken signs token claims using SM2 with SM3 hash and returns the JWS compact form.
func sm2SignToken(claims any, privKey *sm2.PrivateKey) string {
	payload, _ := json.Marshal(claims)

	headerJSON := []byte(`{"alg":"` + crypto.SGD_SM3_SM2 + `"}`)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	signingInput := headerB64 + "." + payloadB64

	h, _ := crypto.GetHashAlgorithm(crypto.SGD_SM3_SM2)
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	sig, _ := crypto.SM2Sign(privKey, digest)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64
}

// sm9SignToken signs token claims using SM9 with SM3 hash and returns the JWS compact form.
func sm9SignToken(claims any, userPrivKey *sm9.SignPrivateKey, uid []byte) string {
	payload, _ := json.Marshal(claims)

	headerJSON := []byte(`{"alg":"` + crypto.SGD_SM3_SM9 + `","uid":"` + string(uid) + `"}`)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	signingInput := headerB64 + "." + payloadB64

	h, _ := crypto.GetHashAlgorithm(crypto.SGD_SM3_SM9)
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	sig, _ := crypto.SM9Sign(userPrivKey, digest)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64
}

// --- SM2 KeySet implementation (for RP-side verification) ---

type sm2KeySet struct {
	pubKey *ecdsa.PublicKey
}

func (s sm2KeySet) VerifySignature(ctx context.Context, rawToken []byte) ([]byte, error) {
	jwsMsg, err := jws.Parse(rawToken)
	if err != nil {
		return nil, err
	}

	sig := jwsMsg.Signatures()[0]
	// Signature() returns the already-decoded raw signature bytes
	sigBytes := sig.Signature()

	signingInput, err := crypto.BuildSigningInput(sig.ProtectedHeaders(), jwsMsg.Payload())
	if err != nil {
		return nil, err
	}

	if err := crypto.VerifySM2JWSSignature(signingInput, sigBytes, s.pubKey); err != nil {
		return nil, err
	}
	return jwsMsg.Payload(), nil
}

// --- SM2 end-to-end tests: OP signs → verifier checks ---

func TestGM_E2E_SM2_SignAndVerify(t *testing.T) {
	privKey, err := crypto.SM2GenerateKey()
	requireNoErr(t, err)
	pubKey := &privKey.PublicKey

	now := time.Now()
	claims := oidc.NewAccessTokenClaims(
		"https://gm.example.com",
		"sm2-user",
		[]string{"gm-client"},
		now.Add(5*time.Minute),
		"jti-sm2-001",
		"gm-client",
		time.Second,
	)

	token := sm2SignToken(claims, privKey)

	verifier := op.NewAccessTokenVerifier(
		"https://gm.example.com",
		sm2KeySet{pubKey: pubKey},
		op.WithSupportedAccessTokenSigningAlgorithms(crypto.SGD_SM3_SM2),
	)

	verified, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](context.Background(), token, verifier)
	requireNoErr(t, err)
	assertEqual(t, claims.GetSubject(), verified.GetSubject())
}

func TestGM_E2E_SM2_WrongKey(t *testing.T) {
	privKey, _ := crypto.SM2GenerateKey()
	otherKey, _ := crypto.SM2GenerateKey()

	claims := oidc.NewAccessTokenClaims(
		"https://gm.example.com", "sm2-user",
		[]string{"gm-client"}, time.Now().Add(5*time.Minute),
		"jti-sm2", "gm-client", time.Second,
	)

	token := sm2SignToken(claims, privKey)

	verifier := op.NewAccessTokenVerifier(
		"https://gm.example.com",
		sm2KeySet{pubKey: &otherKey.PublicKey},
		op.WithSupportedAccessTokenSigningAlgorithms(crypto.SGD_SM3_SM2),
	)

	_, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](context.Background(), token, verifier)
	assertErr(t, err)
}

func TestGM_E2E_SM2_WrongIssuer(t *testing.T) {
	privKey, _ := crypto.SM2GenerateKey()

	claims := oidc.NewAccessTokenClaims(
		"https://evil.example.com", "sm2-user",
		[]string{"gm-client"}, time.Now().Add(5*time.Minute),
		"jti-sm2", "gm-client", time.Second,
	)

	token := sm2SignToken(claims, privKey)

	verifier := op.NewAccessTokenVerifier(
		"https://gm.example.com",
		sm2KeySet{pubKey: &privKey.PublicKey},
		op.WithSupportedAccessTokenSigningAlgorithms(crypto.SGD_SM3_SM2),
	)

	_, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](context.Background(), token, verifier)
	assertErr(t, err)
}

func TestGM_E2E_SM2_ExpiredToken(t *testing.T) {
	privKey, _ := crypto.SM2GenerateKey()

	claims := oidc.NewAccessTokenClaims(
		"https://gm.example.com", "sm2-user",
		[]string{"gm-client"}, time.Now().Add(-time.Hour),
		"jti-sm2", "gm-client", time.Second,
	)

	token := sm2SignToken(claims, privKey)

	verifier := op.NewAccessTokenVerifier(
		"https://gm.example.com",
		sm2KeySet{pubKey: &privKey.PublicKey},
		op.WithSupportedAccessTokenSigningAlgorithms(crypto.SGD_SM3_SM2),
	)

	_, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](context.Background(), token, verifier)
	assertErr(t, err)
}

// --- SM9 end-to-end tests ---

type sm9KeySet struct {
	masterPubKey *sm9.SignMasterPublicKey
}

func (s sm9KeySet) VerifySignature(ctx context.Context, rawToken []byte) ([]byte, error) {
	jwsMsg, err := jws.Parse(rawToken)
	if err != nil {
		return nil, err
	}

	sig := jwsMsg.Signatures()[0]
	sigBytes := sig.Signature()

	signingInput, err := crypto.BuildSigningInput(sig.ProtectedHeaders(), jwsMsg.Payload())
	if err != nil {
		return nil, err
	}

	uidVal, ok := sig.ProtectedHeaders().Field("uid")
	if !ok {
		return nil, errors.New("SM9 signature missing uid")
	}
	uid, ok := uidVal.(string)
	if !ok {
		return nil, errors.New("SM9 uid must be string")
	}

	if err := crypto.VerifySM9JWSSignature(signingInput, sigBytes, s.masterPubKey, []byte(uid)); err != nil {
		return nil, err
	}
	return jwsMsg.Payload(), nil
}

func TestGM_E2E_SM9_SignAndVerify(t *testing.T) {
	masterPrivKey, err := crypto.SM9GenerateSignMasterKey()
	requireNoErr(t, err)
	masterPubKey := masterPrivKey.PublicKey()

	uid := []byte("alice")
	userPrivKey, err := crypto.SM9GenerateSignUserKey(masterPrivKey, uid)
	requireNoErr(t, err)

	now := time.Now()
	claims := oidc.NewAccessTokenClaims(
		"https://gm.example.com",
		"sm9-user",
		[]string{"gm-client"},
		now.Add(5*time.Minute),
		"jti-sm9-001",
		"gm-client",
		time.Second,
	)

	token := sm9SignToken(claims, userPrivKey, uid)

	verifier := op.NewAccessTokenVerifier(
		"https://gm.example.com",
		sm9KeySet{masterPubKey: masterPubKey},
		op.WithSupportedAccessTokenSigningAlgorithms(crypto.SGD_SM3_SM9),
	)

	verified, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](context.Background(), token, verifier)
	requireNoErr(t, err)
	assertEqual(t, claims.GetSubject(), verified.GetSubject())
}

func TestGM_E2E_SM9_WrongUID(t *testing.T) {
	masterPrivKey, _ := crypto.SM9GenerateSignMasterKey()
	masterPubKey := masterPrivKey.PublicKey()

	aliceKey, _ := crypto.SM9GenerateSignUserKey(masterPrivKey, []byte("alice"))

	claims := oidc.NewAccessTokenClaims(
		"https://gm.example.com", "sm9-user",
		[]string{"gm-client"}, time.Now().Add(5*time.Minute),
		"jti-sm9", "gm-client", time.Second,
	)

	// Signed as "bob" but verified as "alice" (uid in header != uid used for verification)
	token := sm9SignToken(claims, aliceKey, []byte("bob"))

	verifier := op.NewAccessTokenVerifier(
		"https://gm.example.com",
		sm9KeySet{masterPubKey: masterPubKey},
		op.WithSupportedAccessTokenSigningAlgorithms(crypto.SGD_SM3_SM9),
	)

	_, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](context.Background(), token, verifier)
	assertErr(t, err)
}

// --- Helper assertions ---

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertEqual(t *testing.T, expected, actual any) {
	t.Helper()
	if expected != actual {
		t.Errorf("expected %v, got %v", expected, actual)
	}
}

func assertErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Error("expected error, got nil")
	}
}
