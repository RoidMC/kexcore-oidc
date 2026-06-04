package client

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/roidmc/kexcore-oidc/pkg/util/http"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// JWTProfileExchange handles the oauth2 jwt profile exchange
func JWTProfileExchange(ctx context.Context, jwtProfileGrantRequest *protocol.JWTProfileGrantRequest, caller TokenEndpointCaller) (*oauth2.Token, error) {
	return CallTokenEndpoint(ctx, jwtProfileGrantRequest, caller)
}

func ClientAssertionCodeOptions(assertion string) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_assertion", assertion),
		oauth2.SetAuthURLParam("client_assertion_type", protocol.ClientAssertionTypeJWTAssertion),
	}
}

func ClientAssertionFormAuthorization(assertion string) http.FormAuthorization {
	return func(values url.Values) {
		values.Set("client_assertion", assertion)
		values.Set("client_assertion_type", protocol.ClientAssertionTypeJWTAssertion)
	}
}
