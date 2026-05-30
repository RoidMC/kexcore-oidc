package op_test

import (
	"testing"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/op"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizeCodeChallenge(t *testing.T) {
	tests := []struct {
		name          string
		codeVerifier  string
		codeChallenge *protocol.CodeChallenge
		want          func(t *testing.T, err error)
	}{
		{
			name:          "missing both code_verifier and code_challenge",
			codeVerifier:  "",
			codeChallenge: nil,
			want: func(t *testing.T, err error) {
				assert.Nil(t, err)
			},
		},
		{
			name:         "valid code_verifier",
			codeVerifier: "Hello World!",
			codeChallenge: &protocol.CodeChallenge{
				Challenge: "f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
				Method:    protocol.CodeChallengeMethodS256,
			},
			want: func(t *testing.T, err error) {
				assert.Nil(t, err)
			},
		},
		{
			name:         "invalid code_verifier",
			codeVerifier: "Hi World!",
			codeChallenge: &protocol.CodeChallenge{
				Challenge: "f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
				Method:    protocol.CodeChallengeMethodS256,
			},
			want: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "invalid code_verifier")
			},
		},
		{
			name:          "code_verifier provided without code_challenge",
			codeVerifier:  "code_verifier",
			codeChallenge: nil,
			want: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "code_verifier unexpectedly provided")
			},
		},
		{
			name:         "empty code_verifier",
			codeVerifier: "",
			codeChallenge: &protocol.CodeChallenge{
				Challenge: "f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
				Method:    protocol.CodeChallengeMethodS256,
			},
			want: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "code_verifier required")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := op.AuthorizeCodeChallenge(tt.codeVerifier, tt.codeChallenge)

			tt.want(t, err)
		})
	}
}
