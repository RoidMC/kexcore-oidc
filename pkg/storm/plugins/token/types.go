package token

import "github.com/roidmc/kexcore-oidc/pkg/protocol"

// tokenExchangeRequest implements storm.TokenExchangeRequest for RFC 8693.
type tokenExchangeRequest struct {
	subject               string
	subjectTokenIDOrToken string
	subjectTokenType      protocol.TokenType
	actorTokenIDOrToken   string
	actorTokenType        protocol.TokenType
	actor                 string
	clientID              string
	audience              []string
	scopes                []string
	requestedTokenType    protocol.TokenType
}

func (r *tokenExchangeRequest) GetSubject() string    { return r.subject }
func (r *tokenExchangeRequest) GetAudience() []string { return r.audience }
func (r *tokenExchangeRequest) GetClientID() string   { return r.clientID }
func (r *tokenExchangeRequest) GetScopes() []string   { return r.scopes }
func (r *tokenExchangeRequest) GetRequestedTokenType() protocol.TokenType {
	return r.requestedTokenType
}
func (r *tokenExchangeRequest) GetSubjectTokenType() protocol.TokenType {
	return r.subjectTokenType
}
func (r *tokenExchangeRequest) GetActorTokenType() protocol.TokenType {
	return r.actorTokenType
}
func (r *tokenExchangeRequest) SetCurrentScopes(scopes []string) { r.scopes = scopes }
func (r *tokenExchangeRequest) SetRequestedTokenType(tt protocol.TokenType) {
	r.requestedTokenType = tt
}
