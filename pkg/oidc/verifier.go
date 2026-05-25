// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package oidc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm9"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/roidmc/kexcore-oidc/pkg/crypto"
)

// Supported JWE key management algorithms (alg).
const (
	JWEAlgDir       = "dir"       // Direct symmetric encryption (no key wrapping)
	JWEAlgA256GCMKW = "A256GCMKW" // AES-256 GCM key wrapping
	JWEAlgSM23      = "SGD_SM2_3" // SM2 public key encryption (GM/T 0125.3)
	JWEAlgSM93      = "SGD_SM9_3" // SM9 identity-based encryption (GM/T 0125.3)
)

// Supported JWE content encryption algorithms (enc).
const (
	JWEEncSM4GCM  = "SGD_SM4_GCM" // SM4-GCM, GM/T 0125.3
	JWEEncA256GCM = "A256GCM"     // AES-256-GCM
	JWEEncA128GCM = "A128GCM"     // AES-128-GCM
)

type Claims interface {
	GetIssuer() string
	GetSubject() string
	GetAudience() []string
	GetExpiration() time.Time
	GetIssuedAt() time.Time
	GetNonce() string
	GetAuthenticationContextClassReference() string
	GetAuthTime() time.Time
	GetAuthorizedParty() string
	ClaimsSignature
}

type ClaimsSignature interface {
	SetSignatureAlgorithm(algorithm string)
}

type IDClaims interface {
	Claims
	GetSignatureAlgorithm() string
	GetAccessTokenHash() string
}

var (
	ErrParse                   = errors.New("parsing of request failed")
	ErrIssuerInvalid           = errors.New("issuer does not match")
	ErrDiscoveryFailed         = errors.New("OpenID Provider Configuration Discovery has failed")
	ErrSubjectMissing          = errors.New("subject missing")
	ErrSubjectInvalid          = errors.New("delegation not allowed, issuer and sub must be identical")
	ErrAudience                = errors.New("audience is not valid")
	ErrAzpMissing              = errors.New("authorized party is not set. If Token is valid for multiple audiences, azp must not be empty")
	ErrAzpInvalid              = errors.New("authorized party is not valid")
	ErrSignatureMissing        = errors.New("id_token does not contain a signature")
	ErrSignatureMultiple       = errors.New("id_token contains multiple signatures")
	ErrSignatureUnsupportedAlg = errors.New("signature algorithm not supported")
	ErrSignatureInvalidPayload = errors.New("signature does not match Payload")
	ErrSignatureInvalid        = errors.New("invalid signature")
	ErrExpired                 = errors.New("token has expired")
	ErrIatMissing              = errors.New("issuedAt of token is missing")
	ErrIatInFuture             = errors.New("issuedAt of token is in the future")
	ErrIatToOld                = errors.New("issuedAt of token is to old")
	ErrNonceInvalid            = errors.New("nonce does not match")
	ErrAcrInvalid              = errors.New("acr is invalid")
	ErrAuthTimeNotPresent      = errors.New("claim `auth_time` of token is missing")
	ErrAuthTimeToOld           = errors.New("auth time of token is too old")
	ErrAtHash                  = errors.New("at_hash does not correspond to access token")
)

// Verifier caries configuration for the various token verification
// functions. Use package specific constructor functions to know
// which values need to be set.
type Verifier struct {
	Issuer            string
	MaxAgeIAT         time.Duration
	Offset            time.Duration
	ClientID          string
	SupportedSignAlgs []string
	MaxAge            time.Duration
	ACR               ACRVerifier
	AZP               AZPVerifier
	KeySet            KeySet
	Nonce             func(ctx context.Context) string
	DecryptionKey     []byte
}

// ACRVerifier specifies the function to be used by the `DefaultVerifier` for validating the acr claim
type ACRVerifier func(string) error

// DefaultACRVerifier implements `ACRVerifier` returning an error
// if none of the provided values matches the acr claim
func DefaultACRVerifier(possibleValues []string) ACRVerifier {
	return func(acr string) error {
		if !slices.Contains(possibleValues, acr) {
			return fmt.Errorf("expected one of: %v, got: %q", possibleValues, acr)
		}
		return nil
	}
}

// DecryptToken detects whether tokenString is a JWE (5-part compact serialization)
// or a plain JWS/signed token. If it is a JWE, decryption needs a key which must be
// provided via context. If no key is available and the token is JWE, an error is returned.
//
// For OP-side decryption (access tokens), use the Crypto interface.
// For RP-side decryption (ID tokens), pass a Decrypter via the verifier options.
func DecryptToken(tokenString string) (string, error) {
	return decryptToken(tokenString, nil)
}

// DecryptTokenWithKey is like DecryptToken but uses the provided key for decryption.
func DecryptTokenWithKey(tokenString string, key []byte) (string, error) {
	return decryptToken(tokenString, key)
}

func decryptToken(tokenString string, key []byte) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) == 3 {
		// Standard JWS (header.payload.signature) — no encryption.
		return tokenString, nil
	}
	if len(parts) == 5 {
		// JWE compact serialization — needs decryption.
		if key == nil {
			return "", errors.New("token is JWE-encrypted but no decryption key provided")
		}

		// Use the existing crypto package to decrypt.
		// Try AES-GCM decryption (the most common case for OP-encrypted tokens).
		plaintext, err := jweDecrypt(tokenString, key)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt JWE token: %w", err)
		}
		return string(plaintext), nil
	}
	// Unknown format — treat as plain token.
	return tokenString, nil
}

// jweDecrypt decrypts a JWE compact serialization using a symmetric key.
// It tries AES256GCM first (standard), then SM4-GCM (GM/T mode).
func jweDecrypt(compact string, key []byte) ([]byte, error) {
	// Try SM4-GCM "dir" mode first (5 parts with empty encrypted key).
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, errors.New("invalid JWE: expected 5 parts")
	}

	// Decode header to determine algorithm
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWE header: %w", err)
	}

	type jweHdr struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}
	var hdr jweHdr
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("failed to parse JWE header: %w", err)
	}

	switch hdr.Alg {
	case JWEAlgDir:
		switch hdr.Enc {
		case JWEEncSM4GCM, JWEEncA256GCM, JWEEncA128GCM:
			return decryptDirMode(compact, key, hdr.Enc)
		}
		return nil, fmt.Errorf("unsupported JWE content encryption: %s", hdr.Enc)
	case JWEAlgA256GCMKW:
		// Use jwx for standard AES-GCM key wrapping
		return decryptAESGCMKW(compact, key)
	default:
		return nil, fmt.Errorf("unsupported JWE algorithm: %s", hdr.Alg)
	}
}

func decryptDirMode(compact string, key []byte, enc string) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if parts[1] != "" {
		return nil, errors.New("expected empty encrypted key for dir mode")
	}

	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("failed to decode tag: %w", err)
	}

	sealed := append(ciphertext, tag...)
	aad := []byte(parts[0])

	// Dispatch decryption based on JWE header "enc" value, NOT key length.
	// Key length is ambiguous (SM4 and AES-128 both use 16 bytes).
	switch enc {
	case JWEEncSM4GCM:
		plaintext, err := crypto.SM4DecryptGCMWithNonce(key, iv, sealed, aad)
		if err != nil {
			return nil, fmt.Errorf("sm4-gcm decrypt failed: %w", err)
		}
		return plaintext, nil
	case JWEEncA128GCM, JWEEncA256GCM:
		plaintext, err := crypto.AESGCMDecrypt(key, iv, sealed, aad)
		if err != nil {
			return nil, fmt.Errorf("aes-gcm decrypt failed: %w", err)
		}
		return plaintext, nil
	default:
		return nil, fmt.Errorf("unsupported JWE content encryption: %s", enc)
	}
}

func decryptAESGCMKW(compact string, key []byte) ([]byte, error) {
	jk, err := jwk.Import[jwk.SymmetricKey](key)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %w", err)
	}
	decrypted, err := jwe.Decrypt([]byte(compact), jwe.WithKey(jwa.A256GCMKW(), jk))
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// EncryptToken wraps a signed JWT (3-part) in JWE "dir" mode using SM4-GCM.
// This is used by the OP to optionally encrypt ID tokens before returning them.
// For AES-GCM, use EncryptTokenA256GCM or EncryptTokenA128GCM.
func EncryptToken(signedToken string, key []byte) (string, error) {
	return encryptTokenDir(signedToken, key, JWEEncSM4GCM)
}

// EncryptTokenA256GCM wraps a signed JWT in JWE "dir" mode using AES-256-GCM.
func EncryptTokenA256GCM(signedToken string, key []byte) (string, error) {
	return encryptTokenDir(signedToken, key, JWEEncA256GCM)
}

// EncryptTokenA128GCM wraps a signed JWT in JWE "dir" mode using AES-128-GCM.
func EncryptTokenA128GCM(signedToken string, key []byte) (string, error) {
	return encryptTokenDir(signedToken, key, JWEEncA128GCM)
}

// EncryptTokenSM2 wraps a signed JWT in JWE using SM2 public-key encryption
// (SGD_SM2_3 key wrapping with SGD_SM4_GCM content encryption) per GM/T 0125.3.
// The publicKey is the recipient's SM2 public key (typically the RP's SM2 key).
func EncryptTokenSM2(signedToken string, publicKey *ecdsa.PublicKey) (string, error) {
	jweToken, err := crypto.SM2EncryptJWE(publicKey, []byte(signedToken))
	if err != nil {
		return "", fmt.Errorf("kexcore/oidc: SM2 JWE encrypt: %w", err)
	}
	return string(jweToken), nil
}

// EncryptTokenSM9 wraps a signed JWT in JWE using SM9 identity-based encryption
// (SGD_SM9_3 key wrapping with SGD_SM4_GCM content encryption) per GM/T 0125.3.
// masterPubKey is the SM9 master public key of the recipient. uid is the
// recipient's identity (used for encryption, can be nil).
func EncryptTokenSM9(signedToken string, masterPubKey *sm9.EncryptMasterPublicKey, uid []byte) (string, error) {
	jweToken, err := crypto.SM9EncryptJWE(masterPubKey, uid, crypto.SGD_SM4_GCM, []byte(signedToken))
	if err != nil {
		return "", fmt.Errorf("kexcore/oidc: SM9 JWE encrypt: %w", err)
	}
	return string(jweToken), nil
}

// encryptTokenDir performs direct symmetric encryption (alg=dir) of a payload.
// It uses the specified content encryption algorithm (enc) to encrypt the payload.
//
// TODO: When adding new ciphers, a registry-based dispatch (map[enc]encryptFunc)
// would eliminate the need to modify the switch statement.
func encryptTokenDir(payload string, key []byte, enc string) (string, error) {
	header := map[string]string{"alg": "dir", "enc": enc}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	var sealed []byte
	switch enc {
	case JWEEncSM4GCM:
		sealed, err = crypto.SM4EncryptGCMWithNonce(key, iv, []byte(payload), []byte(headerB64))
	case JWEEncA128GCM, JWEEncA256GCM:
		sealed, err = crypto.AESGCMEncrypt(key, iv, []byte(payload), []byte(headerB64))
	default:
		return "", fmt.Errorf("unsupported JWE content encryption: %s", enc)
	}
	if err != nil {
		return "", err
	}

	tagSize := 16
	if len(sealed) < tagSize {
		return "", errors.New("encryption output too short")
	}
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	return headerB64 + ".." +
		base64.RawURLEncoding.EncodeToString(iv) + "." +
		base64.RawURLEncoding.EncodeToString(ciphertext) + "." +
		base64.RawURLEncoding.EncodeToString(tag), nil
}

func ParseToken(tokenString string, claims any) ([]byte, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: token contains an invalid number of segments", ErrParse)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed jwt payload: %v", ErrParse, err)
	}
	err = json.Unmarshal(payload, claims)
	return payload, err
}

func CheckSubject(claims Claims) error {
	if claims.GetSubject() == "" {
		return ErrSubjectMissing
	}
	return nil
}

func CheckIssuer(claims Claims, issuer string) error {
	if claims.GetIssuer() != issuer {
		return fmt.Errorf("%w: Expected: %s, got: %s", ErrIssuerInvalid, issuer, claims.GetIssuer())
	}
	return nil
}

func CheckAudience(claims Claims, clientID string) error {
	if !slices.Contains(claims.GetAudience(), clientID) {
		return fmt.Errorf("%w: Audience must contain client_id %q", ErrAudience, clientID)
	}

	// TODO: check aud trusted
	return nil
}

// AZPVerifier specifies the function to be used by the `DefaultVerifier` for validating the azp claim
type AZPVerifier func(string) error

// DefaultAZPVerifier implements `AZPVerifier` returning an error
// if the azp claim is set and doesn't match the clientID.
func DefaultAZPVerifier(clientID string) AZPVerifier {
	return func(azp string) error {
		if azp != "" && azp != clientID {
			return fmt.Errorf("%w: azp %q must be equal to client_id %q", ErrAzpInvalid, azp, clientID)
		}
		return nil
	}
}

// CheckAuthorizedParty checks azp (authorized party) claim requirements.
//
// If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
// If an azp Claim is present, the Client MAY verify that its client_id is the Claim Value.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func CheckAuthorizedParty(claims Claims, clientID string) error {
	return CheckAZPVerifier(claims, DefaultAZPVerifier(clientID))
}

// CheckAZPVerifier checks azp (authorized party) claim requirements.
//
// If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
// If an azp Claim is present, the Client MAY verify that its client_id is the Claim Value.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func CheckAZPVerifier(claims Claims, azp AZPVerifier) error {
	if len(claims.GetAudience()) > 1 {
		if claims.GetAuthorizedParty() == "" {
			return ErrAzpMissing
		}
	}

	if err := azp(claims.GetAuthorizedParty()); err != nil {
		return fmt.Errorf("%w: %v", ErrAzpInvalid, err)
	}
	return nil
}

func CheckSignature(ctx context.Context, token string, payload []byte, claims ClaimsSignature, supportedSigAlgs []string, set KeySet) error {
	jwsMsg, err := jws.Parse([]byte(token))
	if err != nil {
		return ErrParse
	}
	if len(jwsMsg.Signatures()) == 0 {
		return ErrSignatureMissing
	}
	if len(jwsMsg.Signatures()) > 1 {
		return ErrSignatureMultiple
	}
	sig := jwsMsg.Signatures()[0]
	sigAlg, _ := sig.ProtectedHeaders().Algorithm()
	alg := sigAlg.String()

	if !isSupportedSigAlg(alg, supportedSigAlgs) {
		return ErrSignatureUnsupportedAlg
	}

	signedPayload, err := set.VerifySignature(ctx, []byte(token))
	if err != nil {
		return fmt.Errorf("%w (%w)", ErrSignatureInvalid, err)
	}

	if !bytes.Equal(signedPayload, payload) {
		return ErrSignatureInvalidPayload
	}

	claims.SetSignatureAlgorithm(alg)

	return nil
}

func isSupportedSigAlg(alg string, supportedSigAlgs []string) bool {
	if len(supportedSigAlgs) == 0 {
		return true
	}
	for _, a := range supportedSigAlgs {
		if a == alg {
			return true
		}
	}
	return false
}

func CheckExpiration(claims Claims, offset time.Duration) error {
	expiration := claims.GetExpiration()
	if !time.Now().Add(offset).Before(expiration) {
		return ErrExpired
	}
	return nil
}

func CheckIssuedAt(claims Claims, maxAgeIAT, offset time.Duration) error {
	issuedAt := claims.GetIssuedAt()
	if issuedAt.IsZero() {
		return ErrIatMissing
	}
	nowWithOffset := time.Now().Add(offset).Round(time.Second)
	if issuedAt.After(nowWithOffset) {
		return fmt.Errorf("%w: (iat: %v, now with offset: %v)", ErrIatInFuture, issuedAt, nowWithOffset)
	}
	if maxAgeIAT == 0 {
		return nil
	}
	maxAge := time.Now().Add(-maxAgeIAT).Round(time.Second)
	if issuedAt.Before(maxAge) {
		return fmt.Errorf("%w: must not be older than %v, but was %v (%v to old)", ErrIatToOld, maxAge, issuedAt, maxAge.Sub(issuedAt))
	}
	return nil
}

func CheckNonce(claims Claims, nonce string) error {
	if claims.GetNonce() != nonce {
		return fmt.Errorf("%w: expected %q but was %q", ErrNonceInvalid, nonce, claims.GetNonce())
	}
	return nil
}

func CheckAuthorizationContextClassReference(claims Claims, acr ACRVerifier) error {
	if acr != nil {
		if err := acr(claims.GetAuthenticationContextClassReference()); err != nil {
			return fmt.Errorf("%w: %v", ErrAcrInvalid, err)
		}
	}
	return nil
}

func CheckAuthTime(claims Claims, maxAge time.Duration) error {
	if maxAge == 0 {
		return nil
	}
	if claims.GetAuthTime().IsZero() {
		return ErrAuthTimeNotPresent
	}
	authTime := claims.GetAuthTime()
	maxAuthTime := time.Now().Add(-maxAge).Round(time.Second)
	if authTime.Before(maxAuthTime) {
		return fmt.Errorf("%w: must not be older than %v, but was %v (%v to old)", ErrAuthTimeToOld, maxAge, authTime, maxAuthTime.Sub(authTime))
	}
	return nil
}
