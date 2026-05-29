package shared

import (
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type KeyStore = protocol.KeyStore
type Key = protocol.Key
type SigningKey = protocol.SigningKey

type AccessTokenVerifier = protocol.AccessTokenVerifier
type IDTokenHintVerifier = protocol.IDTokenHintVerifier
type IDTokenHintExpiredError = protocol.IDTokenHintExpiredError

var ErrInvalidRefreshToken = protocol.ErrInvalidRefreshToken

var VerifyAccessToken = protocol.VerifyAccessToken
var VerifyIDTokenHint = protocol.VerifyIDTokenHint
var VerifyJWTAssertion = protocol.VerifyJWTAssertion
