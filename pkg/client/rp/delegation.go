package rp

import "github.com/roidmc/kexcore-oidc/v2/pkg/protocol"

// DelegationTokenRequest creates a Token Exchange request for delegation.
// It exchanges an access token for another access token (delegation) for a given resource/audience.
func DelegationTokenRequest(subjectToken string, opts ...func(*protocol.TokenExchangeRequest)) *protocol.TokenExchangeRequest {
	req := &protocol.TokenExchangeRequest{
		GrantType:          protocol.GrantTypeTokenExchange,
		SubjectToken:       subjectToken,
		SubjectTokenType:   protocol.AccessTokenType,
		RequestedTokenType: protocol.AccessTokenType,
	}
	for _, opt := range opts {
		opt(req)
	}
	return req
}
