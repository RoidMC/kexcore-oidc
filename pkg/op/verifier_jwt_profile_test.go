package op_test

import (
	"context"
	"testing"
	"time"

	tu "github.com/roidmc/kexcore-oidc/internal/testutil"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/op"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

func TestNewJWTProfileVerifier(t *testing.T) {
	want := &op.JWTProfileVerifier{
		Verifier: oidc.Verifier{
			Issuer:    tu.ValidIssuer,
			MaxAgeIAT: time.Minute,
			Offset:    time.Second,
		},
		Storage: tu.JWTProfileKeyStorage{},
	}
	got := op.NewJWTProfileVerifier(tu.JWTProfileKeyStorage{}, tu.ValidIssuer, time.Minute, time.Second, op.SubjectCheck(func(request *protocol.JWTTokenRequest) error {
		return protocol.ErrSubjectMissing
	}))
	assert.Equal(t, want.Verifier, got.Verifier)
	assert.Equal(t, want.Storage, got.Storage)
	assert.ErrorIs(t, got.CheckSubject(nil), protocol.ErrSubjectMissing)
}

func TestVerifyJWTAssertion(t *testing.T) {
	errCtx, cancel := context.WithCancel(context.Background())
	cancel()

	verifier := op.NewJWTProfileVerifier(tu.JWTProfileKeyStorage{}, tu.ValidIssuer, time.Minute, 0)
	tests := []struct {
		name     string
		ctx      context.Context
		newToken func() (string, *protocol.JWTTokenRequest)
		wantErr  error
	}{
		{
			name:     "parse error",
			ctx:      context.Background(),
			newToken: func() (string, *protocol.JWTTokenRequest) { return "!", nil },
			wantErr:  protocol.ErrParse,
		},
		{
			name: "wrong audience",
			ctx:  context.Background(),
			newToken: func() (string, *protocol.JWTTokenRequest) {
				return tu.NewJWTProfileAssertion(
					tu.ValidClientID, tu.ValidClientID, []string{"wrong"},
					time.Now(), tu.ValidExpiration,
				)
			},
			wantErr: protocol.ErrAudience,
		},
		{
			name: "expired",
			ctx:  context.Background(),
			newToken: func() (string, *protocol.JWTTokenRequest) {
				return tu.NewJWTProfileAssertion(
					tu.ValidClientID, tu.ValidClientID, []string{tu.ValidIssuer},
					time.Now(), time.Now().Add(-time.Hour),
				)
			},
			wantErr: protocol.ErrExpired,
		},
		{
			name: "invalid iat",
			ctx:  context.Background(),
			newToken: func() (string, *protocol.JWTTokenRequest) {
				return tu.NewJWTProfileAssertion(
					tu.ValidClientID, tu.ValidClientID, []string{tu.ValidIssuer},
					time.Now().Add(time.Hour), tu.ValidExpiration,
				)
			},
			wantErr: protocol.ErrIatInFuture,
		},
		{
			name: "invalid subject",
			ctx:  context.Background(),
			newToken: func() (string, *protocol.JWTTokenRequest) {
				return tu.NewJWTProfileAssertion(
					tu.ValidClientID, "wrong", []string{tu.ValidIssuer},
					time.Now(), tu.ValidExpiration,
				)
			},
			wantErr: protocol.ErrSubjectInvalid,
		},
		{
			name:     "check signature fail",
			ctx:      errCtx,
			newToken: tu.ValidJWTProfileAssertion,
			wantErr:  context.Canceled,
		},
		{
			name:     "ok",
			ctx:      context.Background(),
			newToken: tu.ValidJWTProfileAssertion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertion, want := tt.newToken()
			got, err := op.VerifyJWTAssertion(tt.ctx, assertion, verifier)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}
