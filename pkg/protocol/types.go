package protocol

type AuthMethod string

const (
	AuthMethodBasic         AuthMethod = "client_secret_basic"
	AuthMethodPost          AuthMethod = "client_secret_post"
	AuthMethodNone          AuthMethod = "none"
	AuthMethodPrivateKeyJWT AuthMethod = "private_key_jwt"
)

var AllAuthMethods = []AuthMethod{
	AuthMethodBasic, AuthMethodPost, AuthMethodNone, AuthMethodPrivateKeyJWT,
}
