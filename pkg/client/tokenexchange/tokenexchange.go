package tokenexchange

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/client"
	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	httphelper "github.com/roidmc/kexcore-oidc/pkg/http"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type TokenExchanger interface {
	TokenEndpoint() string
	HttpClient() *http.Client
	AuthFn() (any, error)
}

type OAuthTokenExchange struct {
	httpClient    *http.Client
	tokenEndpoint string
	authFn        func() (any, error)
}

func NewTokenExchanger(ctx context.Context, issuer string, options ...func(source *OAuthTokenExchange)) (TokenExchanger, error) {
	return newOAuthTokenExchange(ctx, issuer, nil, options...)
}

func NewTokenExchangerClientCredentials(ctx context.Context, issuer, clientID, clientSecret string, options ...func(source *OAuthTokenExchange)) (TokenExchanger, error) {
	authorizer := func() (any, error) {
		return httphelper.AuthorizeBasic(clientID, clientSecret), nil
	}
	return newOAuthTokenExchange(ctx, issuer, authorizer, options...)
}

func NewTokenExchangerJWTProfile(ctx context.Context, issuer, clientID string, signer *crypto.Signer, options ...func(source *OAuthTokenExchange)) (TokenExchanger, error) {
	authorizer := func() (any, error) {
		assertion, err := client.SignedJWTProfileAssertion(clientID, []string{issuer}, time.Hour, signer)
		if err != nil {
			return nil, err
		}
		return client.ClientAssertionFormAuthorization(assertion), nil
	}
	return newOAuthTokenExchange(ctx, issuer, authorizer, options...)
}

func newOAuthTokenExchange(ctx context.Context, issuer string, authorizer func() (any, error), options ...func(source *OAuthTokenExchange)) (*OAuthTokenExchange, error) {
	te := &OAuthTokenExchange{
		httpClient: httphelper.DefaultHTTPClient,
	}
	for _, opt := range options {
		opt(te)
	}

	if te.tokenEndpoint == "" {
		config, err := client.Discover(ctx, issuer, te.httpClient)
		if err != nil {
			return nil, err
		}

		te.tokenEndpoint = config.TokenEndpoint
	}

	if te.tokenEndpoint == "" {
		return nil, errors.New("tokenURL is empty: please provide with either `WithStaticTokenEndpoint` or a discovery url")
	}

	te.authFn = authorizer

	return te, nil
}

func WithHTTPClient(client *http.Client) func(*OAuthTokenExchange) {
	return func(source *OAuthTokenExchange) {
		source.httpClient = client
	}
}

func WithStaticTokenEndpoint(issuer, tokenEndpoint string) func(*OAuthTokenExchange) {
	return func(source *OAuthTokenExchange) {
		source.tokenEndpoint = tokenEndpoint
	}
}

func (te *OAuthTokenExchange) TokenEndpoint() string {
	return te.tokenEndpoint
}

func (te *OAuthTokenExchange) HttpClient() *http.Client {
	return te.httpClient
}

func (te *OAuthTokenExchange) AuthFn() (any, error) {
	if te.authFn != nil {
		return te.authFn()
	}

	return nil, nil
}

// ExchangeToken sends a token exchange request (rfc 8693) to te's token endpoint.
// SubjectToken and SubjectTokenType are required parameters.
func ExchangeToken(
	ctx context.Context,
	te TokenExchanger,
	SubjectToken string,
	SubjectTokenType protocol.TokenType,
	ActorToken string,
	ActorTokenType protocol.TokenType,
	Resource []string,
	Audience []string,
	Scopes []string,
	RequestedTokenType protocol.TokenType,
) (*protocol.TokenExchangeResponse, error) {
	ctx, span := client.Tracer.Start(ctx, "ExchangeToken")
	defer span.End()

	if SubjectToken == "" {
		return nil, errors.New("empty subject_token")
	}
	if SubjectTokenType == "" {
		return nil, errors.New("empty subject_token_type")
	}

	authFn, err := te.AuthFn()
	if err != nil {
		return nil, err
	}

	request := protocol.TokenExchangeRequest{
		GrantType:          protocol.GrantTypeTokenExchange,
		SubjectToken:       SubjectToken,
		SubjectTokenType:   SubjectTokenType,
		ActorToken:         ActorToken,
		ActorTokenType:     ActorTokenType,
		Resource:           Resource,
		Audience:           Audience,
		Scopes:             Scopes,
		RequestedTokenType: RequestedTokenType,
	}

	return client.CallTokenExchangeEndpoint(ctx, request, authFn, te)
}
