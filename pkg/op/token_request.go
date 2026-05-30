package op

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"

	httphelper "github.com/roidmc/kexcore-oidc/pkg/http"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type Exchanger interface {
	Storage() Storage
	Decoder() httphelper.Decoder
	Crypto() Crypto
	AuthMethodPostSupported() bool
	AuthMethodPrivateKeyJWTSupported() bool
	GrantTypeRefreshTokenSupported() bool
	GrantTypeTokenExchangeSupported() bool
	GrantTypeJWTAuthorizationSupported() bool
	GrantTypeClientCredentialsSupported() bool
	GrantTypeDeviceCodeSupported() bool
	AccessTokenVerifier(context.Context) *AccessTokenVerifier
	IDTokenHintVerifier(context.Context) *IDTokenHintVerifier
	Logger() *slog.Logger
}

func tokenHandler(exchanger Exchanger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := Tracer.Start(r.Context(), "tokenHandler")
		defer span.End()

		Exchange(w, r.WithContext(ctx), exchanger)
	}
}

// Exchange performs a token exchange appropriate for the grant type
func Exchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	ctx, span := Tracer.Start(r.Context(), "Exchange")
	r = r.WithContext(ctx)
	defer span.End()

	grantType := r.FormValue("grant_type")
	switch grantType {
	case string(protocol.GrantTypeCode):
		CodeExchange(w, r, exchanger)
		return
	case string(protocol.GrantTypeRefreshToken):
		if exchanger.GrantTypeRefreshTokenSupported() {
			RefreshTokenExchange(w, r, exchanger)
			return
		}
	case string(protocol.GrantTypeBearer):
		if ex, ok := exchanger.(JWTAuthorizationGrantExchanger); ok && exchanger.GrantTypeJWTAuthorizationSupported() {
			JWTProfile(w, r, ex)
			return
		}
	case string(protocol.GrantTypeTokenExchange):
		if exchanger.GrantTypeTokenExchangeSupported() {
			TokenExchange(w, r, exchanger)
			return
		}
	case string(protocol.GrantTypeClientCredentials):
		if exchanger.GrantTypeClientCredentialsSupported() {
			ClientCredentialsExchange(w, r, exchanger)
			return
		}
	case string(protocol.GrantTypeDeviceCode):
		if exchanger.GrantTypeDeviceCodeSupported() {
			DeviceAccessToken(w, r, exchanger)
			return
		}
	case "":
		RequestError(w, r, protocol.ErrInvalidRequest().WithDescription("grant_type missing"), exchanger.Logger())
		return
	}
	RequestError(w, r, protocol.ErrUnsupportedGrantType().WithDescription("%s not supported", grantType), exchanger.Logger())
}

// AuthenticatedTokenRequest is a helper interface for ParseAuthenticatedTokenRequest
// it is implemented by protocol.AuthRequest and protocol.RefreshTokenRequest
type AuthenticatedTokenRequest interface {
	SetClientID(string)
	SetClientSecret(string)
}

// ParseAuthenticatedTokenRequest parses the client_id and client_secret from the HTTP request from either
// HTTP Basic Auth header or form body and sets them into the provided authenticatedTokenRequest interface
func ParseAuthenticatedTokenRequest(r *http.Request, decoder httphelper.Decoder, request AuthenticatedTokenRequest) error {
	ctx, span := Tracer.Start(r.Context(), "ParseAuthenticatedTokenRequest")
	defer span.End()
	r = r.WithContext(ctx)

	err := r.ParseForm()
	if err != nil {
		return protocol.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	err = decoder.Decode(request, r.Form)
	if err != nil {
		return protocol.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return nil
	}
	clientID, err = url.QueryUnescape(clientID)
	if err != nil {
		return protocol.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
	}
	clientSecret, err = url.QueryUnescape(clientSecret)
	if err != nil {
		return protocol.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
	}
	request.SetClientID(clientID)
	request.SetClientSecret(clientSecret)
	return nil
}

// AuthorizeClientIDSecret authorizes a client by validating the client_id and client_secret (Basic Auth and POST)
func AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string, storage Storage) error {
	ctx, span := Tracer.Start(ctx, "AuthorizeClientIDSecret")
	defer span.End()

	err := storage.AuthorizeClientIDSecret(ctx, clientID, clientSecret)
	if err != nil {
		return protocol.ErrInvalidClient().WithDescription("invalid client_id / client_secret").WithParent(err)
	}
	return nil
}

// AuthorizeCodeChallenge authorizes a client by validating the code_verifier against the previously sent
// code_challenge of the auth request (PKCE)
func AuthorizeCodeChallenge(codeVerifier string, challenge *protocol.CodeChallenge) error {
	if challenge == nil {
		if codeVerifier != "" {
			return protocol.ErrInvalidRequest().WithDescription("code_verifier unexpectedly provided")
		}

		return nil
	}

	if codeVerifier == "" {
		return protocol.ErrInvalidRequest().WithDescription("code_verifier required")
	}
	if !protocol.VerifyCodeChallenge(challenge, codeVerifier) {
		return protocol.ErrInvalidGrant().WithDescription("invalid code_verifier")
	}
	return nil
}

// AuthorizePrivateJWTKey authorizes a client by validating the client_assertion's signature with a previously
// registered public key (JWT Profile)
func AuthorizePrivateJWTKey(ctx context.Context, clientAssertion string, exchanger JWTAuthorizationGrantExchanger) (Client, error) {
	ctx, span := Tracer.Start(ctx, "AuthorizePrivateJWTKey")
	defer span.End()

	jwtReq, err := VerifyJWTAssertion(ctx, clientAssertion, exchanger.JWTProfileVerifier(ctx))
	if err != nil {
		return nil, err
	}
	client, err := exchanger.Storage().GetClientByClientID(ctx, jwtReq.Issuer)
	if err != nil {
		return nil, err
	}
	if client.AuthMethod() != protocol.AuthMethodPrivateKeyJWT {
		return nil, protocol.ErrInvalidClient()
	}
	return client, nil
}

// ValidateGrantType ensures that the requested grant_type is allowed by the client
func ValidateGrantType(client interface{ GrantTypes() []protocol.GrantType }, grantType protocol.GrantType) bool {
	if client == nil {
		return false
	}
	for _, grant := range client.GrantTypes() {
		if grantType == grant {
			return true
		}
	}
	return false
}
