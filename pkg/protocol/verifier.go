package protocol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// JWE key wrapping algorithms supported by this package.
const (
	JWEAlgDir       = "dir"       // Direct use of a shared symmetric key (RFC 7518 §4.5)
	JWEAlgA256GCMKW = "A256GCMKW" // AES-256-GCM key wrapping (RFC 7518 §4.7)
	JWEAlgSM23      = "SGD_SM2_3" // SM2 key wrapping per GM/T 0125.3
	JWEAlgSM93      = "SGD_SM9_3" // SM9 identity-based key wrapping per GM/T 0125.3
)

// JWE content encryption algorithms supported by this package.
const (
	JWEEncSM4GCM  = "SGD_SM4_GCM" // SM4-GCM content encryption per GM/T 0125.3
	JWEEncA256GCM = "A256GCM"     // AES-256-GCM content encryption (RFC 7518 §5.3)
	JWEEncA128GCM = "A128GCM"     // AES-128-GCM content encryption (RFC 7518 §5.3)
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

type AccessTokenVerifier struct {
	Issuer            string
	KeySet            KeySet
	KeyStore          KeyStore // optional, used for JWKS-based verification
	Offset            time.Duration
	SupportedSignAlgs []string
	MaxAgeIAT         time.Duration
}

type AccessTokenVerifierOpt func(*AccessTokenVerifier)

func WithSupportedAccessTokenSigningAlgorithms(algs ...string) AccessTokenVerifierOpt {
	return func(v *AccessTokenVerifier) {
		v.SupportedSignAlgs = algs
	}
}

func NewAccessTokenVerifier(issuer string, keySet KeySet, opts ...AccessTokenVerifierOpt) *AccessTokenVerifier {
	v := &AccessTokenVerifier{
		Issuer: issuer,
		KeySet: keySet,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// resolveKeySet returns the effective KeySet for signature verification.
// If KeySet is set directly, use it. Otherwise wrap KeyStore in an adapter.
func (v *AccessTokenVerifier) resolveKeySet() KeySet {
	if v.KeySet != nil {
		return v.KeySet
	}
	if v.KeyStore != nil {
		return &keyStoreAdapter{store: v.KeyStore}
	}
	return nil
}

type IDTokenHintVerifier struct {
	Issuer            string
	KeySet            KeySet
	KeyStore          KeyStore // optional, used for JWKS-based verification
	Offset            time.Duration
	MaxAgeIAT         time.Duration
	MaxAge            time.Duration
	SupportedSignAlgs []string
	ACR               ACRVerifier
}

type IDTokenHintVerifierOpt func(*IDTokenHintVerifier)

func WithSupportedIDTokenHintSigningAlgorithms(algs ...string) IDTokenHintVerifierOpt {
	return func(v *IDTokenHintVerifier) {
		v.SupportedSignAlgs = algs
	}
}

func NewIDTokenHintVerifier(issuer string, keySet KeySet, opts ...IDTokenHintVerifierOpt) *IDTokenHintVerifier {
	v := &IDTokenHintVerifier{
		Issuer: issuer,
		KeySet: keySet,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// resolveKeySet returns the effective KeySet for signature verification.
func (v *IDTokenHintVerifier) resolveKeySet() KeySet {
	if v.KeySet != nil {
		return v.KeySet
	}
	if v.KeyStore != nil {
		return &keyStoreAdapter{store: v.KeyStore}
	}
	return nil
}

type IDTokenHintExpiredError struct {
	Err error
}

func (e IDTokenHintExpiredError) Error() string { return e.Err.Error() }
func (e IDTokenHintExpiredError) Unwrap() error { return e.Err }
func (e IDTokenHintExpiredError) Is(err error) bool {
	t, ok := err.(IDTokenHintExpiredError)
	if !ok {
		return false
	}
	return errors.Is(e.Err, t.Err)
}

var ErrInvalidRefreshToken = errors.New("invalid refresh token")

// --- audience type (handles JSON string or array) ---

type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

// --- amr type (handles JSON string or array) ---

type amr []string

func (a *amr) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

// --- internal claim structs for verification ---

type accessTokenClaims struct {
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   audience `json:"aud,omitempty"`
	Expiration int64    `json:"exp,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	AuthTime   int64    `json:"auth_time,omitempty"`
	Nonce      string   `json:"nonce,omitempty"`
	JWTID      string   `json:"jti,omitempty"`
	AZP        string   `json:"azp,omitempty"`
	ACR        string   `json:"acr,omitempty"`
	AMR        amr      `json:"amr,omitempty"`
	ClientID   string   `json:"client_id,omitempty"`
	SigAlg     string   `json:"-"`
}

func (c *accessTokenClaims) GetIssuer() string                              { return c.Issuer }
func (c *accessTokenClaims) GetSubject() string                             { return c.Subject }
func (c *accessTokenClaims) GetAudience() []string                          { return []string(c.Audience) }
func (c *accessTokenClaims) GetExpiration() time.Time                       { return time.Unix(c.Expiration, 0) }
func (c *accessTokenClaims) GetIssuedAt() time.Time                         { return time.Unix(c.IssuedAt, 0) }
func (c *accessTokenClaims) GetNonce() string                               { return c.Nonce }
func (c *accessTokenClaims) GetAuthenticationContextClassReference() string { return c.ACR }
func (c *accessTokenClaims) GetAuthTime() time.Time                         { return time.Unix(c.AuthTime, 0) }
func (c *accessTokenClaims) GetAuthorizedParty() string                     { return c.AZP }
func (c *accessTokenClaims) SetSignatureAlgorithm(alg string)               { c.SigAlg = alg }

// --- DecryptToken / EncryptToken ---

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
		return tokenString, nil
	}
	if len(parts) == 5 {
		if key == nil {
			return "", errors.New("token is JWE-encrypted but no decryption key provided")
		}
		plaintext, err := DecryptTokenJWE(tokenString, key)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt JWE token: %w", err)
		}
		return string(plaintext), nil
	}
	return tokenString, nil
}

// EncryptToken wraps a signed JWT (3-part) in JWE "dir" mode using SM4-GCM.
// This is used by the OP to optionally encrypt ID tokens before returning them.
// For AES-GCM, use EncryptTokenA256GCM or EncryptTokenA128GCM.
func EncryptToken(signedToken string, key []byte) (string, error) {
	return EncryptTokenJWE(signedToken, key, JWEAlgDir, JWEEncSM4GCM)
}

// EncryptTokenA256GCM wraps a signed JWT in JWE "dir" mode using AES-256-GCM.
func EncryptTokenA256GCM(signedToken string, key []byte) (string, error) {
	return EncryptTokenJWE(signedToken, key, JWEAlgDir, JWEEncA256GCM)
}

// EncryptTokenA128GCM wraps a signed JWT in JWE "dir" mode using AES-128-GCM.
func EncryptTokenA128GCM(signedToken string, key []byte) (string, error) {
	return EncryptTokenJWE(signedToken, key, JWEAlgDir, JWEEncA128GCM)
}

// EncryptTokenSM2 wraps a signed JWT in JWE using SM2 public-key encryption
// (SGD_SM2_3 key wrapping with SGD_SM4_GCM content encryption) per GM/T 0125.3.
// The publicKey is the recipient's SM2 public key (typically the RP's SM2 key).
func EncryptTokenSM2(signedToken string, publicKey interface{}) (string, error) {
	return EncryptTokenJWE(signedToken, publicKey, JWEAlgSM23, JWEEncSM4GCM)
}

// EncryptTokenSM9 wraps a signed JWT in JWE using SM9 identity-based encryption
// (SGD_SM9_3 key wrapping with SGD_SM4_GCM content encryption) per GM/T 0125.3.
// sm9Key is an SM9EncryptKey that provides the master public key and UID.
func EncryptTokenSM9(signedToken string, sm9Key SM9EncryptKey) (string, error) {
	return EncryptTokenJWE(signedToken, sm9Key, JWEAlgSM93, JWEEncSM4GCM)
}

// --- ParseToken ---

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

// --- Check functions ---

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

// --- Verify* functions ---

func VerifyAccessToken(ctx context.Context, token string, v *AccessTokenVerifier) (tokenID, subject string, ok bool) {
	decrypted, err := DecryptToken(token)
	if err != nil {
		return "", "", false
	}
	claims := new(accessTokenClaims)
	payload, err := ParseToken(decrypted, claims)
	if err != nil {
		return "", "", false
	}
	if err := CheckIssuer(claims, v.Issuer); err != nil {
		return "", "", false
	}
	keySet := v.resolveKeySet()
	if err := CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs, keySet); err != nil {
		return "", "", false
	}
	if err := CheckExpiration(claims, v.Offset); err != nil {
		return "", "", false
	}
	return claims.JWTID, claims.GetSubject(), true
}

// VerifyAccessTokenGeneric validates the access token and returns typed claims.
func VerifyAccessTokenGeneric[C Claims](ctx context.Context, token string, v *AccessTokenVerifier) (claims C, err error) {
	var nilClaims C

	decrypted, err := DecryptToken(token)
	if err != nil {
		return nilClaims, err
	}
	payload, err := ParseToken(decrypted, &claims)
	if err != nil {
		return nilClaims, err
	}

	if err := CheckIssuer(claims, v.Issuer); err != nil {
		return nilClaims, err
	}

	keySet := v.resolveKeySet()
	if err = CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs, keySet); err != nil {
		return nilClaims, err
	}

	if err = CheckExpiration(claims, v.Offset); err != nil {
		return nilClaims, err
	}

	return claims, nil
}

func VerifyIDTokenHint(ctx context.Context, token string, v *IDTokenHintVerifier) (*IDTokenClaims, error) {
	decrypted, err := DecryptToken(token)
	if err != nil {
		return nil, err
	}
	claims := new(IDTokenClaims)
	payload, err := ParseToken(decrypted, claims)
	if err != nil {
		return nil, err
	}
	if err := CheckIssuer(claims, v.Issuer); err != nil {
		return nil, err
	}
	keySet := v.resolveKeySet()
	if err := CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs, keySet); err != nil {
		return nil, err
	}
	if err := CheckAuthorizationContextClassReference(claims, v.ACR); err != nil {
		return nil, err
	}
	if err := CheckExpiration(claims, v.Offset); err != nil {
		return claims, &IDTokenHintExpiredError{Err: err}
	}
	if err := CheckIssuedAt(claims, v.MaxAgeIAT, v.Offset); err != nil {
		return claims, &IDTokenHintExpiredError{Err: err}
	}
	if err := CheckAuthTime(claims, v.MaxAge); err != nil {
		return claims, &IDTokenHintExpiredError{Err: err}
	}
	return claims, nil
}

// VerifyIDTokenHintGeneric validates the ID token hint and returns typed claims.
func VerifyIDTokenHintGeneric[C Claims](ctx context.Context, token string, v *IDTokenHintVerifier) (claims C, err error) {
	var nilClaims C

	decrypted, err := DecryptToken(token)
	if err != nil {
		return nilClaims, err
	}
	payload, err := ParseToken(decrypted, &claims)
	if err != nil {
		return nilClaims, err
	}

	if err := CheckIssuer(claims, v.Issuer); err != nil {
		return nilClaims, err
	}

	keySet := v.resolveKeySet()
	if err = CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs, keySet); err != nil {
		return nilClaims, err
	}

	if err = CheckAuthorizationContextClassReference(claims, v.ACR); err != nil {
		return nilClaims, err
	}

	if err = CheckExpiration(claims, v.Offset); err != nil {
		return claims, &IDTokenHintExpiredError{Err: err}
	}

	if err = CheckIssuedAt(claims, v.MaxAgeIAT, v.Offset); err != nil {
		return claims, &IDTokenHintExpiredError{Err: err}
	}

	if err = CheckAuthTime(claims, v.MaxAge); err != nil {
		return claims, &IDTokenHintExpiredError{Err: err}
	}
	return claims, nil
}

func VerifyJWTAssertion(ctx context.Context, assertion string, issuer string, ks KeyStore, offset time.Duration) (*JWTTokenRequest, error) {
	request := new(JWTTokenRequest)
	payload, err := ParseToken(assertion, request)
	if err != nil {
		return nil, err
	}
	if err := CheckAudience(request, issuer); err != nil {
		return nil, err
	}
	if err := CheckExpiration(request, offset); err != nil {
		return nil, err
	}
	if request.Issuer != request.Subject {
		return nil, ErrSubjectInvalid
	}
	keySet := &keyStoreAdapter{store: ks}
	if err := CheckSignature(ctx, assertion, payload, request, nil, keySet); err != nil {
		return nil, err
	}
	return request, nil
}

// CheckSignatureWithKeyStore verifies a JWT signature using a KeyStore.
// It adapts the KeyStore to a KeySet internally and delegates to CheckSignature.
func CheckSignatureWithKeyStore(ctx context.Context, token string, payload []byte, claims ClaimsSignature, supportedSigAlgs []string, store KeyStore) error {
	return CheckSignature(ctx, token, payload, claims, supportedSigAlgs, &keyStoreAdapter{store: store})
}

// --- keyStoreAdapter ---

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
	keyID, alg := GetKeyIDAndAlg(jwsMsg)
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
	key, err := FindMatchingKey(keyID, KeyUseSignature, alg, jwkKeys...)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	return VerifySignature(ctx, jwsMsg, rawToken, key, alg)
}
