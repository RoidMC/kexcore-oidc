package protocol

import (
	"crypto/sha256"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
)

type CodeChallengeMethod string

const (
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
	CodeChallengeMethodS256  CodeChallengeMethod = "S256"
)

type CodeChallenge struct {
	Challenge string
	Method    CodeChallengeMethod
}

func NewSHACodeChallenge(code string) string {
	return crypto.HashString(sha256.New(), code, false)
}

func VerifyCodeChallenge(c *CodeChallenge, codeVerifier string) bool {
	if c == nil {
		return false
	}
	if c.Method == CodeChallengeMethodS256 {
		codeVerifier = NewSHACodeChallenge(codeVerifier)
	}
	return codeVerifier == c.Challenge
}
