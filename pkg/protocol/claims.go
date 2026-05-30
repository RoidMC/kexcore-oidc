package protocol

import "time"

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
