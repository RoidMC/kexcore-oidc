package rp

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// TokenExchangeRP extends the `RelyingParty` interface for OAuth 2.0 Token Exchange (RFC 8693).
type TokenExchangeRP interface {
	RelyingParty

	// TokenExchange implements the Token Exchange Grant, exchanging one token for another.
	TokenExchange(context.Context, *protocol.TokenExchangeRequest) (*oauth2.Token, error)
}

// DelegationTokenExchangeRP extends the `TokenExchangeRP` interface
// for the specific delegation token request.
type DelegationTokenExchangeRP interface {
	TokenExchangeRP

	// DelegationTokenExchange implements the Token Exchange Grant,
	// providing an access token in request for a delegation token for a given resource/audience.
	DelegationTokenExchange(context.Context, *protocol.TokenExchangeRequest) (*oauth2.Token, error)
}
