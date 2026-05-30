package protocol

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

const (
	JWEAlgDir       = "dir"
	JWEAlgA256GCMKW = "A256GCMKW"
	JWEAlgSM23      = "SGD_SM2_3"
	JWEAlgSM93      = "SGD_SM9_3"
)

const (
	JWEEncSM4GCM  = "SGD_SM4_GCM"
	JWEEncA256GCM = "A256GCM"
	JWEEncA128GCM = "A128GCM"
)

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

type ACRVerifier func(string) error

func DefaultACRVerifier(possibleValues []string) ACRVerifier {
	return func(acr string) error {
		if !slices.Contains(possibleValues, acr) {
			return fmt.Errorf("expected one of: %v, got: %q", possibleValues, acr)
		}
		return nil
	}
}

type AZPVerifier func(string) error

func DefaultAZPVerifier(clientID string) AZPVerifier {
	return func(azp string) error {
		if azp != "" && azp != clientID {
			return fmt.Errorf("%w: azp %q must be equal to client_id %q", ErrAzpInvalid, azp, clientID)
		}
		return nil
	}
}

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

type IDTokenClaims struct {
	Issuer          string   `json:"iss,omitempty"`
	Subject         string   `json:"sub,omitempty"`
	Audience        audience `json:"aud,omitempty"`
	Expiration      int64    `json:"exp,omitempty"`
	IssuedAt        int64    `json:"iat,omitempty"`
	AuthTime        int64    `json:"auth_time,omitempty"`
	NotBefore       int64    `json:"nbf,omitempty"`
	Nonce           string   `json:"nonce,omitempty"`
	AZP             string   `json:"azp,omitempty"`
	ACR             string   `json:"acr,omitempty"`
	AMR             amr      `json:"amr,omitempty"`
	ClientID        string   `json:"client_id,omitempty"`
	AccessTokenHash string   `json:"at_hash,omitempty"`
	CodeHash        string   `json:"c_hash,omitempty"`
	SessionID       string   `json:"sid,omitempty"`
	SigAlg          string   `json:"-"`
}

func (c *IDTokenClaims) GetIssuer() string                              { return c.Issuer }
func (c *IDTokenClaims) GetSubject() string                             { return c.Subject }
func (c *IDTokenClaims) GetAudience() []string                          { return []string(c.Audience) }
func (c *IDTokenClaims) GetExpiration() time.Time                       { return time.Unix(c.Expiration, 0) }
func (c *IDTokenClaims) GetIssuedAt() time.Time                         { return time.Unix(c.IssuedAt, 0) }
func (c *IDTokenClaims) GetNonce() string                               { return c.Nonce }
func (c *IDTokenClaims) GetAuthenticationContextClassReference() string { return c.ACR }
func (c *IDTokenClaims) GetAuthTime() time.Time                         { return time.Unix(c.AuthTime, 0) }
func (c *IDTokenClaims) GetAuthorizedParty() string                     { return c.AZP }
func (c *IDTokenClaims) SetSignatureAlgorithm(alg string)               { c.SigAlg = alg }
func (c *IDTokenClaims) GetSignatureAlgorithm() string                  { return c.SigAlg }
func (c *IDTokenClaims) GetAccessTokenHash() string                     { return c.AccessTokenHash }

// --- DecryptToken / EncryptToken ---

func DecryptToken(tokenString string) (string, error) {
	return decryptToken(tokenString, nil)
}

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
		plaintext, err := jweDecrypt(tokenString, key)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt JWE token: %w", err)
		}
		return string(plaintext), nil
	}
	return tokenString, nil
}

func jweDecrypt(compact string, key []byte) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, errors.New("invalid JWE: expected 5 parts")
	}
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

func EncryptToken(signedToken string, key []byte) (string, error) {
	return encryptTokenDir(signedToken, key, JWEEncSM4GCM)
}

func EncryptTokenA256GCM(signedToken string, key []byte) (string, error) {
	return encryptTokenDir(signedToken, key, JWEEncA256GCM)
}

func EncryptTokenA128GCM(signedToken string, key []byte) (string, error) {
	return encryptTokenDir(signedToken, key, JWEEncA128GCM)
}

func EncryptTokenSM2(signedToken string, publicKey *ecdsa.PublicKey) (string, error) {
	jweToken, err := crypto.SM2EncryptJWE(publicKey, []byte(signedToken))
	if err != nil {
		return "", fmt.Errorf("kexcore/protocol: SM2 JWE encrypt: %w", err)
	}
	return string(jweToken), nil
}

func EncryptTokenSM9(signedToken string, masterPubKey *sm9.EncryptMasterPublicKey, uid []byte) (string, error) {
	jweToken, err := crypto.SM9EncryptJWE(masterPubKey, uid, crypto.SGD_SM4_GCM, []byte(signedToken))
	if err != nil {
		return "", fmt.Errorf("kexcore/protocol: SM9 JWE encrypt: %w", err)
	}
	return string(jweToken), nil
}

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
	return nil
}

func CheckAuthorizedParty(claims Claims, clientID string) error {
	return CheckAZPVerifier(claims, DefaultAZPVerifier(clientID))
}

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
	keySet := &keyStoreAdapter{store: v.KeyStore}
	if err := CheckSignature(ctx, decrypted, payload, claims, nil, keySet); err != nil {
		return "", "", false
	}
	if err := CheckExpiration(claims, v.Offset); err != nil {
		return "", "", false
	}
	return claims.JWTID, claims.GetSubject(), true
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
	keySet := &keyStoreAdapter{store: v.KeyStore}
	if err := CheckSignature(ctx, decrypted, payload, claims, nil, keySet); err != nil {
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
