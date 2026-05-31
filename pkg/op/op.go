// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package op

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/emmansun/gmsm/sm9"
	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/roidmc/kexcore-oidc/internal/otel"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/rs/cors"
	"github.com/zitadel/schema"
	"golang.org/x/text/language"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	httphelper "github.com/roidmc/kexcore-oidc/pkg/http"
)

const (
	healthEndpoint               = "/healthz"
	readinessEndpoint            = "/ready"
	authCallbackPathSuffix       = "/callback"
	defaultAuthorizationEndpoint = "authorize"
	defaultTokenEndpoint         = "oauth/token"
	defaultIntrospectEndpoint    = "oauth/introspect"
	defaultUserinfoEndpoint      = "userinfo"
	defaultRevocationEndpoint    = "revoke"
	defaultEndSessionEndpoint    = "end_session"
	defaultKeysEndpoint          = "keys"
	defaultDeviceAuthzEndpoint   = "/device_authorization"
	defaultPushedAuthEndpoint    = "pushed_authorization_request"
	defaultRegistrationEndpoint  = "register"
)

var (
	DefaultEndpoints = &Endpoints{
		Authorization:              NewEndpoint(defaultAuthorizationEndpoint),
		Token:                      NewEndpoint(defaultTokenEndpoint),
		Introspection:              NewEndpoint(defaultIntrospectEndpoint),
		Userinfo:                   NewEndpoint(defaultUserinfoEndpoint),
		Revocation:                 NewEndpoint(defaultRevocationEndpoint),
		EndSession:                 NewEndpoint(defaultEndSessionEndpoint),
		JwksURI:                    NewEndpoint(defaultKeysEndpoint),
		DeviceAuthorization:        NewEndpoint(defaultDeviceAuthzEndpoint),
		PushedAuthorizationRequest: NewEndpoint(defaultPushedAuthEndpoint),
		// Dynamic Client Registration (RFC 7591)
		Registration: NewEndpoint(defaultRegistrationEndpoint),
	}

	DefaultSupportedClaims = []string{
		"sub",
		"aud",
		"exp",
		"iat",
		"iss",
		"auth_time",
		"nonce",
		"acr",
		"amr",
		"c_hash",
		"at_hash",
		"act",
		"scopes",
		"client_id",
		"azp",
		"preferred_username",
		"name",
		"family_name",
		"given_name",
		"locale",
		"email",
		"email_verified",
		"phone_number",
		"phone_number_verified",
	}

	defaultCORSOptions = cors.Options{
		AllowCredentials: true,
		AllowedHeaders: []string{
			"Origin",
			"Accept",
			"Accept-Language",
			"Authorization",
			"Content-Type",
			"X-Requested-With",
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodHead,
			http.MethodPost,
		},
		ExposedHeaders: []string{
			"Location",
			"Content-Length",
		},
		AllowOriginFunc: func(_ string) bool {
			return true
		},
	}
)

var Tracer = otel.Tracer("github.com/zitadel/oidc/pkg/op")

type OpenIDProvider interface {
	http.Handler
	Configuration
	Storage() Storage
	Decoder() httphelper.Decoder
	Encoder() httphelper.Encoder
	IDTokenHintVerifier(context.Context) *IDTokenHintVerifier
	AccessTokenVerifier(context.Context) *AccessTokenVerifier
	Crypto() Crypto
	DefaultLogoutRedirectURI() string
	Probes() []ProbesFn
	Logger() *slog.Logger
}

type HttpInterceptor func(http.Handler) http.Handler

type corsOptioner interface {
	CORSOptions() *cors.Options
}

func CreateRouter(o OpenIDProvider, interceptors ...HttpInterceptor) chi.Router {
	router := chi.NewRouter()
	if co, ok := o.(corsOptioner); ok {
		if opts := co.CORSOptions(); opts != nil {
			router.Use(cors.New(*opts).Handler)
		}
	} else {
		router.Use(cors.New(defaultCORSOptions).Handler)
	}
	router.Use(intercept(o.IssuerFromRequest, interceptors...))
	router.HandleFunc(healthEndpoint, healthHandler)
	router.HandleFunc(readinessEndpoint, readyHandler(o.Probes()))
	router.HandleFunc(protocol.DiscoveryEndpoint, discoveryHandler(o, o.Storage()))
	router.HandleFunc(o.AuthorizationEndpoint().Relative(), authorizeHandler(o))
	router.HandleFunc(authCallbackPath(o), AuthorizeCallbackHandler(o))
	router.HandleFunc(o.TokenEndpoint().Relative(), tokenHandler(o))
	router.HandleFunc(o.IntrospectionEndpoint().Relative(), introspectionHandler(o))
	router.HandleFunc(o.UserinfoEndpoint().Relative(), userinfoHandler(o))
	router.HandleFunc(o.RevocationEndpoint().Relative(), revocationHandler(o))
	router.HandleFunc(o.EndSessionEndpoint().Relative(), endSessionHandler(o))
	router.HandleFunc(o.KeysEndpoint().Relative(), keysHandler(o.Storage()))
	router.HandleFunc(o.DeviceAuthorizationEndpoint().Relative(), DeviceAuthorizationHandler(o))
	if o.RegistrationSupported() {
		router.Post(o.RegistrationEndpoint().Relative(), RegisterClientHandler(o))
		// RFC 7592 client configuration endpoint (GET, PUT, DELETE)
		router.Route(o.RegistrationEndpoint().Relative()+"/{client_id}", func(r chi.Router) {
			r.Get("/", ClientConfigurationHandler(o))
			r.Put("/", UpdateClientConfigurationHandler(o))
			r.Delete("/", DeleteClientConfigurationHandler(o))
		})
	}
	return router
}

// AuthCallbackURL builds the url for the redirect (with the requestID) after a successful login
func AuthCallbackURL(o OpenIDProvider) func(context.Context, string) string {
	return func(ctx context.Context, requestID string) string {
		return o.AuthorizationEndpoint().Absolute(IssuerFromContext(ctx)) + authCallbackPathSuffix + "?id=" + requestID
	}
}

func authCallbackPath(o OpenIDProvider) string {
	return o.AuthorizationEndpoint().Relative() + authCallbackPathSuffix
}

type Config struct {
	CryptoKey                         [32]byte // for encrypting access token via NewAESCrypto; will be overwritten by WithCrypto
	CryptoKeyId                       string
	DefaultLogoutRedirectURI          string
	CodeMethodS256                    bool
	AuthMethodPost                    bool
	AuthMethodPrivateKeyJWT           bool
	GrantTypeRefreshToken             bool
	RequestObjectSupported            bool
	SupportedUILocales                []language.Tag
	SupportedClaims                   []string
	SupportedScopes                   []string
	SupportedSignAlgorithms           []string
	DeviceAuthorization               DeviceAuthorizationConfig
	BackChannelLogoutSupported        bool
	BackChannelLogoutSessionSupported bool
	PushedAuthRequestSupported        bool
	// RequirePushedAuthorizationRequests indicates that the authorization server
	// accepts authorization requests only via PAR (RFC 9126 Section 10.2).
	RequirePushedAuthorizationRequests bool
	// Dynamic Client Registration (RFC 7591)
	RegistrationSupported bool
}

// Endpoints defines endpoint routes.
type Endpoints struct {
	Authorization              *Endpoint
	Token                      *Endpoint
	Introspection              *Endpoint
	Userinfo                   *Endpoint
	Revocation                 *Endpoint
	EndSession                 *Endpoint
	CheckSessionIframe         *Endpoint
	BackChannelLogout          *Endpoint
	JwksURI                    *Endpoint
	DeviceAuthorization        *Endpoint
	PushedAuthorizationRequest *Endpoint
	// Dynamic Client Registration (RFC 7591)
	Registration *Endpoint
}

// NewProvider creates a provider with a router on it's embedded http.Handler.
// Issuer is a function that must return the issuer on every request.
// Typically [StaticIssuer], [IssuerFromHost] or [IssuerFromForwardedOrHost] can be used.
//
// The router handles a suite of endpoints (some paths can be overridden):
//
//	/healthz
//	/ready
//	/.well-known/openid-configuration
//	/oauth/token
//	/oauth/introspect
//	/callback
//	/authorize
//	/userinfo
//	/revoke
//	/end_session
//	/keys
//	/device_authorization
//
// This does not include login. Login is handled with a redirect that includes the
// request ID. The redirect for logins is specified per-client by Client.LoginURL().
// Successful logins should mark the request as authorized and redirect back to
// op.AuthCallbackURL(provider) which is probably /callback. On the redirect back
// to the AuthCallbackURL, the request id should be passed as the "id" parameter.
func NewProvider(
	config *Config,
	storage Storage,
	issuer func(insecure bool) (IssuerFromRequest, error),
	opOpts ...Option,
) (_ *Provider, err error) {
	keySet := &OpenIDKeySet{storage}
	easgcmCrypto := NewAES256GCMCrypto(config.CryptoKey, config.CryptoKeyId)
	crypto := NewCompositeCrypto(
		easgcmCrypto,
		[]Decrypter{
			easgcmCrypto,
			NewAESCrypto(config.CryptoKey),
		},
	)
	o := &Provider{
		config:            config,
		storage:           storage,
		accessTokenKeySet: keySet,
		idTokenHinKeySet:  keySet,
		crypto:            crypto,
		endpoints:         DefaultEndpoints,
		timer:             make(<-chan time.Time),
		corsOpts:          &defaultCORSOptions,
		logger:            slog.Default(),
	}

	for _, optFunc := range opOpts {
		if err := optFunc(o); err != nil {
			return nil, err
		}
	}

	// If SupportedSignAlgorithms is not explicitly configured, populate it
	// from storage so that all discovery fields stay consistent with the
	// actual signing keys (id_token_signing_alg, request_object_signing_alg, etc.).
	if len(o.config.SupportedSignAlgorithms) == 0 {
		algs, err := storage.SignatureAlgorithms(context.Background())
		if err == nil && len(algs) > 0 {
			o.config.SupportedSignAlgorithms = algs
		}
	}

	o.issuer, err = issuer(o.insecure)
	if err != nil {
		return nil, err
	}
	o.Handler = CreateRouter(o, o.interceptors...)
	o.decoder = schema.NewDecoder()
	o.decoder.IgnoreUnknownKeys(true)
	o.encoder = protocol.NewEncoder()
	return o, nil
}

type Provider struct {
	http.Handler
	config                  *Config
	issuer                  IssuerFromRequest
	insecure                bool
	endpoints               *Endpoints
	storage                 Storage
	accessTokenKeySet       protocol.KeySet
	idTokenHinKeySet        protocol.KeySet
	crypto                  Crypto
	decoder                 *schema.Decoder
	encoder                 httphelper.Encoder
	interceptors            []HttpInterceptor
	timer                   <-chan time.Time
	accessTokenVerifierOpts []AccessTokenVerifierOpt
	idTokenHintVerifierOpts []IDTokenHintVerifierOpt
	corsOpts                *cors.Options
	logger                  *slog.Logger
}

func (o *Provider) IssuerFromRequest(r *http.Request) string {
	return o.issuer(r)
}

func (o *Provider) Insecure() bool {
	return o.insecure
}

func (o *Provider) AuthorizationEndpoint() *Endpoint {
	return o.endpoints.Authorization
}

func (o *Provider) TokenEndpoint() *Endpoint {
	return o.endpoints.Token
}

func (o *Provider) IntrospectionEndpoint() *Endpoint {
	return o.endpoints.Introspection
}

func (o *Provider) UserinfoEndpoint() *Endpoint {
	return o.endpoints.Userinfo
}

func (o *Provider) RevocationEndpoint() *Endpoint {
	return o.endpoints.Revocation
}

func (o *Provider) EndSessionEndpoint() *Endpoint {
	return o.endpoints.EndSession
}

func (o *Provider) DeviceAuthorizationEndpoint() *Endpoint {
	return o.endpoints.DeviceAuthorization
}

func (o *Provider) CheckSessionIframe() *Endpoint {
	return o.endpoints.CheckSessionIframe
}

func (o *Provider) KeysEndpoint() *Endpoint {
	return o.endpoints.JwksURI
}

func (o *Provider) AuthMethodPostSupported() bool {
	return o.config.AuthMethodPost
}

func (o *Provider) CodeMethodS256Supported() bool {
	return o.config.CodeMethodS256
}

func (o *Provider) AuthMethodPrivateKeyJWTSupported() bool {
	return o.config.AuthMethodPrivateKeyJWT
}

func (o *Provider) TokenEndpointSigningAlgorithmsSupported() []string {
	return supportedSignAlgorithms(o.config.SupportedSignAlgorithms)
}

func (o *Provider) GrantTypeRefreshTokenSupported() bool {
	return o.config.GrantTypeRefreshToken
}

func (o *Provider) GrantTypeTokenExchangeSupported() bool {
	_, ok := o.storage.(TokenExchangeStorage)
	return ok
}

func (o *Provider) GrantTypeJWTAuthorizationSupported() bool {
	return true
}

func (o *Provider) GrantTypeDeviceCodeSupported() bool {
	_, ok := o.storage.(DeviceAuthorizationStorage)
	return ok
}

func (o *Provider) IntrospectionAuthMethodPrivateKeyJWTSupported() bool {
	return true
}

func (o *Provider) IntrospectionEndpointSigningAlgorithmsSupported() []string {
	return supportedSignAlgorithms(o.config.SupportedSignAlgorithms)
}

func (o *Provider) GrantTypeClientCredentialsSupported() bool {
	_, ok := o.storage.(ClientCredentialsStorage)
	return ok
}

func (o *Provider) RevocationAuthMethodPrivateKeyJWTSupported() bool {
	return true
}

func (o *Provider) RevocationEndpointSigningAlgorithmsSupported() []string {
	return supportedSignAlgorithms(o.config.SupportedSignAlgorithms)
}

func (o *Provider) RequestObjectSupported() bool {
	return o.config.RequestObjectSupported
}

func (o *Provider) RequestObjectSigningAlgorithmsSupported() []string {
	return supportedSignAlgorithms(o.config.SupportedSignAlgorithms)
}

func supportedSignAlgorithms(algs []string) []string {
	if len(algs) == 0 {
		return []string{"RS256"}
	}
	return algs
}

func (o *Provider) SupportedUILocales() []language.Tag {
	return o.config.SupportedUILocales
}

func (o *Provider) DeviceAuthorization() DeviceAuthorizationConfig {
	return o.config.DeviceAuthorization
}

func (o *Provider) BackChannelLogoutSupported() bool {
	return o.config.BackChannelLogoutSupported
}

func (o *Provider) BackChannelLogoutSessionSupported() bool {
	return o.config.BackChannelLogoutSessionSupported
}

func (o *Provider) PushedAuthRequestSupported() bool {
	return o.config.PushedAuthRequestSupported
}

func (o *Provider) RequirePushedAuthorizationRequests() bool {
	return o.config.RequirePushedAuthorizationRequests
}

func (o *Provider) PushedAuthRequestEndpoint() *Endpoint {
	return o.endpoints.PushedAuthorizationRequest
}

// RegistrationSupported returns true if Dynamic Client Registration is enabled.
func (o *Provider) RegistrationSupported() bool {
	return o.config.RegistrationSupported
}

// RegistrationEndpoint returns the registration endpoint.
func (o *Provider) RegistrationEndpoint() *Endpoint {
	return o.endpoints.Registration
}

func (o *Provider) Storage() Storage {
	return o.storage
}

func (o *Provider) Decoder() httphelper.Decoder {
	return o.decoder
}

func (o *Provider) Encoder() httphelper.Encoder {
	return o.encoder
}

func (o *Provider) IDTokenHintVerifier(ctx context.Context) *IDTokenHintVerifier {
	return NewIDTokenHintVerifier(IssuerFromContext(ctx), o.idTokenHinKeySet, o.idTokenHintVerifierOpts...)
}

func (o *Provider) JWTProfileVerifier(ctx context.Context) *JWTProfileVerifier {
	return NewJWTProfileVerifier(o.Storage(), IssuerFromContext(ctx), 1*time.Hour, time.Second)
}

func (o *Provider) AccessTokenVerifier(ctx context.Context) *AccessTokenVerifier {
	return NewAccessTokenVerifier(IssuerFromContext(ctx), o.accessTokenKeySet, o.accessTokenVerifierOpts...)
}

func (o *Provider) Crypto() Crypto {
	return o.crypto
}

func (o *Provider) DefaultLogoutRedirectURI() string {
	return o.config.DefaultLogoutRedirectURI
}

func (o *Provider) Probes() []ProbesFn {
	return []ProbesFn{
		ReadyStorage(o.Storage()),
	}
}

func (o *Provider) CORSOptions() *cors.Options {
	return o.corsOpts
}

func (o *Provider) Logger() *slog.Logger {
	return o.logger
}

type OpenIDKeySet struct {
	Storage
}

// VerifySignature implements the protocol.KeySet interface
// providing an implementation for the keys stored in the OP Storage interface
func (o *OpenIDKeySet) VerifySignature(ctx context.Context, rawToken []byte) ([]byte, error) {
	keySet, err := o.Storage.KeySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching keys: %w", err)
	}

	// Parse to get kid and alg from header
	jwsMsg, err := jws.Parse(rawToken)
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	keyID, alg := protocol.GetKeyIDAndAlg(jwsMsg)

	// SM9 keys cannot be imported into jwx (identity-based cryptography).
	// Find the matching key directly from the storage keySet.
	if crypto.IsSM9Algorithm(alg) {
		for _, k := range keySet {
			if (keyID == "" || k.ID() == keyID) && crypto.IsSM9Algorithm(k.Algorithm()) {
				return verifySM9Signature(jwsMsg, k)
			}
		}
		return nil, fmt.Errorf("no matching SM9 key found for kid=%q", keyID)
	}

	// Convert []Key to []jwk.Key
	var jwkKeys []jwk.Key
	for _, k := range keySet {
		jk, err := jwk.Import[jwk.Key](k.Key())
		if err != nil {
			continue
		}
		if id := k.ID(); id != "" {
			_ = jk.Set(jwk.KeyIDKey, id)
		}
		if use := k.Use(); use != "" {
			_ = jk.Set(jwk.KeyUsageKey, use)
		}
		jwkKeys = append(jwkKeys, jk)
	}

	key, err := protocol.FindMatchingKey(keyID, protocol.KeyUseSignature, alg, jwkKeys...)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	// SM2 signatures use custom verification since jwx does not support SM2.
	if crypto.IsSM2Algorithm(alg) {
		return verifySM2Signature(jwsMsg, key)
	}

	sig := jwsMsg.Signatures()[0]
	sigAlg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return nil, fmt.Errorf("missing algorithm in token header")
	}
	payload, err := jws.Verify(rawToken, jws.WithKey(sigAlg, key))
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// verifySM2Signature verifies an SM2 JWS signature using SM3 hash.
func verifySM2Signature(jwsMsg *jws.Message, key jwk.Key) ([]byte, error) {
	sig := jwsMsg.Signatures()[0]
	sigBytes, err := base64.RawURLEncoding.DecodeString(string(sig.Signature()))
	if err != nil {
		return nil, fmt.Errorf("error decoding SM2 signature: %w", err)
	}

	signingInput, err := crypto.BuildSigningInput(sig.ProtectedHeaders(), jwsMsg.Payload())
	if err != nil {
		return nil, err
	}

	raw, err := jwk.Export[any](key)
	if err != nil {
		return nil, fmt.Errorf("error extracting public key: %w", err)
	}
	pubKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PublicKey, got %T", raw)
	}

	if err := crypto.VerifySM2JWSSignature(signingInput, sigBytes, pubKey); err != nil {
		return nil, err
	}
	return jwsMsg.Payload(), nil
}

// verifySM9Signature verifies an SM9 JWS signature using SM3 hash.
// SM9 is identity-based: verification requires the master public key + uid.
// The uid must be present in the JWS protected header as a custom "uid" parameter.
func verifySM9Signature(jwsMsg *jws.Message, key Key) ([]byte, error) {
	sig := jwsMsg.Signatures()[0]
	sigBytes, err := base64.RawURLEncoding.DecodeString(string(sig.Signature()))
	if err != nil {
		return nil, fmt.Errorf("error decoding SM9 signature: %w", err)
	}

	signingInput, err := crypto.BuildSigningInput(sig.ProtectedHeaders(), jwsMsg.Payload())
	if err != nil {
		return nil, err
	}

	raw := key.Key()
	masterPubKey, ok := raw.(*sm9.SignMasterPublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *sm9.SignMasterPublicKey, got %T", raw)
	}

	uidVal, ok := sig.ProtectedHeaders().Field("uid")
	if !ok {
		return nil, fmt.Errorf("SM9 signature missing required 'uid' header parameter")
	}
	uid, ok := uidVal.(string)
	if !ok {
		return nil, fmt.Errorf("SM9 'uid' header parameter must be a string, got %T", uidVal)
	}

	if err := crypto.VerifySM9JWSSignature(signingInput, sigBytes, masterPubKey, []byte(uid)); err != nil {
		return nil, err
	}
	return jwsMsg.Payload(), nil
}

type Option func(o *Provider) error

// WithAllowInsecure allows the use of http (instead of https) for issuers
// this is not recommended for production use and violates the OIDC specification
func WithAllowInsecure() Option {
	return func(o *Provider) error {
		o.insecure = true
		return nil
	}
}

func WithCustomAuthEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Authorization = endpoint
		return nil
	}
}

func WithCustomTokenEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Token = endpoint
		return nil
	}
}

func WithCustomIntrospectionEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Introspection = endpoint
		return nil
	}
}

func WithCustomUserinfoEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Userinfo = endpoint
		return nil
	}
}

func WithCustomRevocationEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Revocation = endpoint
		return nil
	}
}

func WithCustomEndSessionEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.EndSession = endpoint
		return nil
	}
}

func WithCustomKeysEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.JwksURI = endpoint
		return nil
	}
}

func WithCustomDeviceAuthorizationEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.DeviceAuthorization = endpoint
		return nil
	}
}

// WithCustomRegistrationEndpoint allows overriding the default registration endpoint.
func WithCustomRegistrationEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Registration = endpoint
		return nil
	}
}

// WithRegistrationSupported enables Dynamic Client Registration (RFC 7591).
// This will register the /register endpoint and advertise it in the Discovery document.
// Note that this requires the Storage to implement [ClientRegistrationStorage].
func WithRegistrationSupported() Option {
	return func(o *Provider) error {
		o.config.RegistrationSupported = true
		return nil
	}
}

// WithCustomEndpoints sets multiple endpoints at once.
// None of the endpoints may be nil, or an error will
// be returned when the Option used by the Provider.
func WithCustomEndpoints(auth, token, userInfo, revocation, endSession, keys *Endpoint) Option {
	return func(o *Provider) error {
		for _, e := range []*Endpoint{auth, token, userInfo, revocation, endSession, keys} {
			if err := e.Validate(); err != nil {
				return err
			}
		}
		o.endpoints.Authorization = auth
		o.endpoints.Token = token
		o.endpoints.Userinfo = userInfo
		o.endpoints.Revocation = revocation
		o.endpoints.EndSession = endSession
		o.endpoints.JwksURI = keys
		return nil
	}
}

func WithHttpInterceptors(interceptors ...HttpInterceptor) Option {
	return func(o *Provider) error {
		o.interceptors = append(o.interceptors, interceptors...)
		return nil
	}
}

// WithAccessTokenKeySet allows passing a KeySet with public keys for Access Token verification.
// The default KeySet uses the [Storage] interface
func WithAccessTokenKeySet(keySet protocol.KeySet) Option {
	return func(o *Provider) error {
		o.accessTokenKeySet = keySet
		return nil
	}
}

func WithAccessTokenVerifierOpts(opts ...AccessTokenVerifierOpt) Option {
	return func(o *Provider) error {
		o.accessTokenVerifierOpts = opts
		return nil
	}
}

// WithIDTokenHintKeySet allows passing a KeySet with public keys for ID Token Hint verification.
// The default KeySet uses the [Storage] interface.
func WithIDTokenHintKeySet(keySet protocol.KeySet) Option {
	return func(o *Provider) error {
		o.idTokenHinKeySet = keySet
		return nil
	}
}

func WithIDTokenHintVerifierOpts(opts ...IDTokenHintVerifierOpt) Option {
	return func(o *Provider) error {
		o.idTokenHintVerifierOpts = opts
		return nil
	}
}

func WithCORSOptions(opts *cors.Options) Option {
	return func(o *Provider) error {
		o.corsOpts = opts
		return nil
	}
}

// WithLogger lets a logger other than slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(o *Provider) error {
		o.logger = logger
		return nil
	}
}

// WithCrypto allows the user to pass their own Crypto implementation.
//
// If provided, this will overwrite Config.CryptoKey.
func WithCrypto(crypto Crypto) Option {
	return func(o *Provider) error {
		o.crypto = crypto
		return nil
	}
}

func intercept(i IssuerFromRequest, interceptors ...HttpInterceptor) func(handler http.Handler) http.Handler {
	issuerInterceptor := NewIssuerInterceptor(i)
	return func(handler http.Handler) http.Handler {
		for i := len(interceptors) - 1; i >= 0; i-- {
			handler = interceptors[i](handler)
		}
		return issuerInterceptor.Handler(handler)
	}
}
