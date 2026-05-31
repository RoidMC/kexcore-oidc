package op

import (
	"context"
	"errors"
	"testing"
	"time"

	tu "github.com/roidmc/kexcore-oidc/internal/testutil"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
		
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIDTokenHintVerifier(t *testing.T) {
	type args struct {
		issuer string
		keySet protocol.KeySet
		opts   []IDTokenHintVerifierOpt
	}
	tests := []struct {
		name string
		args args
		want *IDTokenHintVerifier
	}{
		{
			name: "simple",
			args: args{
				issuer: tu.ValidIssuer,
				keySet: tu.KeySet{},
			},
			want: &IDTokenHintVerifier{
				Issuer: tu.ValidIssuer,
				KeySet: tu.KeySet{},
			},
		},
		{
			name: "with signature algorithm",
			args: args{
				issuer: tu.ValidIssuer,
				keySet: tu.KeySet{},
				opts: []IDTokenHintVerifierOpt{
					WithSupportedIDTokenHintSigningAlgorithms("ABC", "DEF"),
				},
			},
			want: &IDTokenHintVerifier{
				Issuer:            tu.ValidIssuer,
				KeySet:            tu.KeySet{},
				SupportedSignAlgs: []string{"ABC", "DEF"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewIDTokenHintVerifier(tt.args.issuer, tt.args.keySet, tt.args.opts...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_IDTokenHintExpiredError(t *testing.T) {
	var err error = IDTokenHintExpiredError{protocol.ErrExpired}
	assert.True(t, errors.Unwrap(err) == protocol.ErrExpired)
	assert.ErrorIs(t, err, protocol.ErrExpired)
	assert.ErrorAs(t, err, &IDTokenHintExpiredError{})
}

func TestVerifyIDTokenHint(t *testing.T) {
	verifier := &IDTokenHintVerifier{
		Issuer:            tu.ValidIssuer,
		MaxAgeIAT:         2 * time.Minute,
		Offset:            time.Second,
		SupportedSignAlgs: []string{string(tu.SignatureAlgorithm)},
		MaxAge:            2 * time.Minute,
		ACR:               tu.ACRVerify,
		KeySet:            tu.KeySet{},
	}

	tests := []struct {
		name        string
		tokenClaims func() (string, *protocol.IDTokenClaims)
		wantClaims  bool
		wantErr     error
	}{
		{
			name:        "success",
			tokenClaims: tu.ValidIDToken,
			wantClaims:  true,
		},
		{
			name:        "parse err",
			tokenClaims: func() (string, *protocol.IDTokenClaims) { return "~~~~", nil },
			wantErr:     protocol.ErrParse,
		},
		{
			name:        "invalid signature",
			tokenClaims: func() (string, *protocol.IDTokenClaims) { return tu.InvalidSignatureToken, nil },
			wantErr:     protocol.ErrSignatureUnsupportedAlg,
		},
		{
			name: "wrong issuer",
			tokenClaims: func() (string, *protocol.IDTokenClaims) {
				return tu.NewIDToken(
					"foo", tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantErr: protocol.ErrIssuerInvalid,
		},
		{
			name: "wrong acr",
			tokenClaims: func() (string, *protocol.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					"else", tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantErr: protocol.ErrAcrInvalid,
		},
		{
			name: "expired",
			tokenClaims: func() (string, *protocol.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration.Add(-time.Hour), tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantClaims: true,
			wantErr:    IDTokenHintExpiredError{protocol.ErrExpired},
		},
		{
			name: "IAT too old",
			tokenClaims: func() (string, *protocol.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, time.Hour, "",
				)
			},
			wantClaims: true,
			wantErr:    IDTokenHintExpiredError{protocol.ErrIatToOld},
		},
		{
			name: "expired auth",
			tokenClaims: func() (string, *protocol.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime.Add(-time.Hour), tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantClaims: true,
			wantErr:    IDTokenHintExpiredError{protocol.ErrAuthTimeToOld},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, want := tt.tokenClaims()

			got, err := VerifyIDTokenHint[*protocol.IDTokenClaims](context.Background(), token, verifier)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantClaims {
				assert.Equal(t, got, want, "claims")
				return
			}
			assert.Nil(t, got, "claims")
		})
	}
}
