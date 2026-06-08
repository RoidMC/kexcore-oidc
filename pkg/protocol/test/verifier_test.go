package protocol_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	tu "github.com/roidmc/kexcore-oidc/internal/testutil"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptToken(t *testing.T) {
	const tokenString = "ABC"
	got, err := protocol.DecryptToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, tokenString, got)
}

func TestDefaultACRVerifier(t *testing.T) {
	acrVerifier := protocol.DefaultACRVerifier([]string{"foo", "bar"})

	tests := []struct {
		name    string
		acr     string
		wantErr string
	}{
		{
			name: "ok",
			acr:  "bar",
		},
		{
			name:    "error",
			acr:     "hello",
			wantErr: "expected one of: [foo bar], got: \"hello\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := acrVerifier(tt.acr)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNewAccessTokenVerifier(t *testing.T) {
	type args struct {
		issuer string
		keySet protocol.KeySet
		opts   []protocol.AccessTokenVerifierOpt
	}
	tests := []struct {
		name string
		args args
		want *protocol.AccessTokenVerifier
	}{
		{
			name: "simple",
			args: args{
				issuer: tu.ValidIssuer,
				keySet: tu.KeySet{},
			},
			want: &protocol.AccessTokenVerifier{
				Issuer: tu.ValidIssuer,
				KeySet: tu.KeySet{},
			},
		},
		{
			name: "with signature algorithm",
			args: args{
				issuer: tu.ValidIssuer,
				keySet: tu.KeySet{},
				opts: []protocol.AccessTokenVerifierOpt{
					protocol.WithSupportedAccessTokenSigningAlgorithms("ABC", "DEF"),
				},
			},
			want: &protocol.AccessTokenVerifier{
				Issuer:            tu.ValidIssuer,
				KeySet:            tu.KeySet{},
				SupportedSignAlgs: []string{"ABC", "DEF"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.NewAccessTokenVerifier(tt.args.issuer, tt.args.keySet, tt.args.opts...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVerifyAccessTokenGeneric(t *testing.T) {
	verifier := &protocol.AccessTokenVerifier{
		Issuer:            tu.ValidIssuer,
		MaxAgeIAT:         2 * time.Minute,
		Offset:            time.Second,
		SupportedSignAlgs: []string{string(tu.SignatureAlgorithm)},
		KeySet:            tu.KeySet{},
	}

	tests := []struct {
		name        string
		tokenClaims func() (string, *protocol.AccessTokenClaims)
		wantErr     bool
	}{
		{
			name:        "success",
			tokenClaims: tu.ValidAccessToken,
		},
		{
			name:        "parse err",
			tokenClaims: func() (string, *protocol.AccessTokenClaims) { return "~~~~", nil },
			wantErr:     true,
		},
		{
			name:        "invalid signature",
			tokenClaims: func() (string, *protocol.AccessTokenClaims) { return tu.InvalidSignatureToken, nil },
			wantErr:     true,
		},
		{
			name: "wrong issuer",
			tokenClaims: func() (string, *protocol.AccessTokenClaims) {
				return tu.NewAccessToken(
					"foo", tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidJWTID, tu.ValidClientID,
					tu.ValidSkew,
				)
			},
			wantErr: true,
		},
		{
			name: "expired",
			tokenClaims: func() (string, *protocol.AccessTokenClaims) {
				return tu.NewAccessToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration.Add(-time.Hour), tu.ValidJWTID, tu.ValidClientID,
					tu.ValidSkew,
				)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, want := tt.tokenClaims()

			got, err := protocol.VerifyAccessTokenGeneric[*protocol.AccessTokenClaims](context.Background(), token, verifier)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, got, want)
		})
	}
}

func TestNewIDTokenHintVerifier(t *testing.T) {
	type args struct {
		issuer string
		keySet protocol.KeySet
		opts   []protocol.IDTokenHintVerifierOpt
	}
	tests := []struct {
		name string
		args args
		want *protocol.IDTokenHintVerifier
	}{
		{
			name: "simple",
			args: args{
				issuer: tu.ValidIssuer,
				keySet: tu.KeySet{},
			},
			want: &protocol.IDTokenHintVerifier{
				Issuer: tu.ValidIssuer,
				KeySet: tu.KeySet{},
			},
		},
		{
			name: "with signature algorithm",
			args: args{
				issuer: tu.ValidIssuer,
				keySet: tu.KeySet{},
				opts: []protocol.IDTokenHintVerifierOpt{
					protocol.WithSupportedIDTokenHintSigningAlgorithms("ABC", "DEF"),
				},
			},
			want: &protocol.IDTokenHintVerifier{
				Issuer:            tu.ValidIssuer,
				KeySet:            tu.KeySet{},
				SupportedSignAlgs: []string{"ABC", "DEF"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.NewIDTokenHintVerifier(tt.args.issuer, tt.args.keySet, tt.args.opts...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIDTokenHintExpiredError(t *testing.T) {
	var err error = protocol.IDTokenHintExpiredError{Err: protocol.ErrExpired}
	assert.True(t, errors.Unwrap(err) == protocol.ErrExpired)
	assert.ErrorIs(t, err, protocol.ErrExpired)
	assert.ErrorAs(t, err, &protocol.IDTokenHintExpiredError{})
}

func TestVerifyIDTokenHintGeneric(t *testing.T) {
	verifier := &protocol.IDTokenHintVerifier{
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
			wantErr:    protocol.IDTokenHintExpiredError{Err: protocol.ErrExpired},
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
			wantErr:    protocol.IDTokenHintExpiredError{Err: protocol.ErrIatToOld},
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
			wantErr:    protocol.IDTokenHintExpiredError{Err: protocol.ErrAuthTimeToOld},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, want := tt.tokenClaims()

			got, err := protocol.VerifyIDTokenHintGeneric[*protocol.IDTokenClaims](context.Background(), token, verifier)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantClaims {
				assert.Equal(t, got, want, "claims")
				return
			}
			assert.Nil(t, got, "claims")
		})
	}
}

func TestParseToken(t *testing.T) {
	token, wantClaims := tu.ValidIDToken()
	wantClaims.SignatureAlg = "" // unset, because is not part of the JSON payload

	wantPayload, err := json.Marshal(wantClaims)
	require.NoError(t, err)

	tests := []struct {
		name        string
		tokenString string
		wantErr     bool
	}{
		{
			name:        "split error",
			tokenString: "nope",
			wantErr:     true,
		},
		{
			name:        "base64 error",
			tokenString: "foo.~.bar",
			wantErr:     true,
		},
		{
			name:        "success",
			tokenString: token,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotClaims := new(protocol.IDTokenClaims)
			gotPayload, err := protocol.ParseToken(tt.tokenString, gotClaims)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, wantClaims, gotClaims)
			assert.JSONEq(t, string(wantPayload), string(gotPayload))
		})
	}
}

func TestCheckSubject(t *testing.T) {
	tests := []struct {
		name    string
		claims  protocol.Claims
		wantErr error
	}{
		{
			name:    "missing",
			claims:  &protocol.TokenClaims{},
			wantErr: protocol.ErrSubjectMissing,
		},
		{
			name: "ok",
			claims: &protocol.TokenClaims{
				Subject: "foo",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.CheckSubject(tt.claims)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func ExampleVerifyAccessTokenGeneric_customClaims() {
	type Nested struct {
		Count int      `json:"count,omitempty"`
		Tags  []string `json:"tags,omitempty"`
	}
	type MyCustomClaims struct {
		protocol.TokenClaims
		Foo string  `json:"foo,omitempty"`
		Bar *Nested `json:"bar,omitempty"`
	}

	/*
	   accessToken carries the following claims. foo and bar are custom claims

	   	{
	   		"aud": [
	   			"unit",
	   			"test"
	   		],
	   		"bar": {
	   			"count": 22,
	   			"tags": [
	   				"some",
	   				"tags"
	   			]
	   		},
	   		"exp": 4802234675,
	   		"foo": "Hello, World!",
	   		"iat": 1678097014,
	   		"iss": "local.com",
	   		"jti": "9876",
	   		"nbf": 1678097014,
	   		"sub": "tim@local.com"
	   	}
	*/

	const accessToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOlsidW5pdCIsInRlc3QiXSwiYmFyIjp7ImNvdW50IjoyMiwidGFncyI6WyJzb21lIiwidGFncyJdfSwiZXhwIjo0ODAyMjM0Njc1LCJmb28iOiJIZWxsbywgV29ybGQhIiwiaWF0IjoxNjc4MDk3MDE0LCJpc3MiOiJsb2NhbC5jb20iLCJqdGkiOiI5ODc2IiwibmJmIjoxNjc4MDk3MDE0LCJzdWIiOiJ0aW1AbG9jYWwuY29tIn0.OUgk-B7OXjYlYFj-nogqSDJiQE19tPrbzqUHEAjcEiJkaWo6-IpGVfDiGKm-TxjXQsNScxpaY0Pg3XIh1xK6TgtfYtoLQm-5RYw_mXgb9xqZB2VgPs6nNEYFUDM513MOU0EBc0QMyqAEGzW-HiSPAb4ugCvkLtM1yo11Xyy6vksAdZNs_mJDT4X3vFXnr0jk0ugnAW6fTN3_voC0F_9HQUAkmd750OIxkAHxAMvEPQcpbLHenVvX_Q0QMrzClVrxehn5TVMfmkYYg7ocr876Bq9xQGPNHAcrwvVIJqdg5uMUA38L3HC2BEueG6furZGvc7-qDWAT1VR9liM5ieKpPg`

	v := protocol.NewAccessTokenVerifier("local.com", tu.KeySet{})
	claims, err := protocol.VerifyAccessTokenGeneric[*MyCustomClaims](context.TODO(), accessToken, v)
	if err != nil {
		panic(err)
	}
	fmt.Println(claims.Foo, claims.Bar.Count, claims.Bar.Tags)
	// Output: Hello, World! 22 [some tags]
}

func TestCheckIssuer(t *testing.T) {
	const issuer = "foo.bar"
	tests := []struct {
		name    string
		claims  protocol.Claims
		wantErr error
	}{
		{
			name:    "missing",
			claims:  &protocol.TokenClaims{},
			wantErr: protocol.ErrIssuerInvalid,
		},
		{
			name: "wrong",
			claims: &protocol.TokenClaims{
				Issuer: "wrong",
			},
			wantErr: protocol.ErrIssuerInvalid,
		},
		{
			name: "ok",
			claims: &protocol.TokenClaims{
				Issuer: issuer,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.CheckIssuer(tt.claims, issuer)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckAudience(t *testing.T) {
	const clientID = "foo.bar"
	tests := []struct {
		name    string
		claims  protocol.Claims
		wantErr error
	}{
		{
			name:    "missing",
			claims:  &protocol.TokenClaims{},
			wantErr: protocol.ErrAudience,
		},
		{
			name: "wrong",
			claims: &protocol.TokenClaims{
				Audience: []string{"wrong"},
			},
			wantErr: protocol.ErrAudience,
		},
		{
			name: "ok",
			claims: &protocol.TokenClaims{
				Audience: []string{clientID},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.CheckAudience(tt.claims, clientID)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckAuthorizedParty(t *testing.T) {
	const clientID = "foo.bar"
	tests := []struct {
		name    string
		claims  protocol.Claims
		azp     protocol.AZPVerifier
		wantErr error
	}{
		{
			name: "single audience, no azp",
			claims: &protocol.TokenClaims{
				Audience: []string{clientID},
			},
		},
		{
			name: "multiple audience, no azp",
			claims: &protocol.TokenClaims{
				Audience: []string{clientID, "other"},
			},
			wantErr: protocol.ErrAzpMissing,
		},
		{
			name: "single audience, with azp",
			claims: &protocol.TokenClaims{
				Audience:        []string{clientID},
				AuthorizedParty: clientID,
			},
		},
		{
			name: "multiple audience, with azp",
			claims: &protocol.TokenClaims{
				Audience:        []string{clientID, "other"},
				AuthorizedParty: clientID,
			},
		},
		{
			name: "custom azp",
			claims: &protocol.TokenClaims{
				Audience:        []string{"not-client-id"},
				AuthorizedParty: clientID,
			},
			azp: func(s string) error {
				// skip check.
				return nil
			},
		},
		{
			name: "wrong azp",
			claims: &protocol.TokenClaims{
				AuthorizedParty: "wrong",
			},
			wantErr: protocol.ErrAzpInvalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			azp := tt.azp
			if azp == nil {
				azp = protocol.DefaultAZPVerifier(clientID)
			}
			err := protocol.CheckAZPVerifier(tt.claims, azp)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckSignature(t *testing.T) {
	errCtx, cancel := context.WithCancel(context.Background())
	cancel()

	token, _ := tu.ValidIDToken()
	payload, err := protocol.ParseToken(token, &protocol.IDTokenClaims{})
	require.NoError(t, err)

	type args struct {
		ctx              context.Context
		token            string
		payload          []byte
		supportedSigAlgs []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "parse error",
			args: args{
				ctx:     context.Background(),
				token:   "~",
				payload: payload,
			},
			wantErr: protocol.ErrParse,
		},
		{
			name: "default sigAlg",
			args: args{
				ctx:     context.Background(),
				token:   token,
				payload: payload,
			},
		},
		{
			name: "unsupported sigAlg",
			args: args{
				ctx:              context.Background(),
				token:            token,
				payload:          payload,
				supportedSigAlgs: []string{"foo", "bar"},
			},
			wantErr: protocol.ErrSignatureUnsupportedAlg,
		},
		{
			name: "verify error",
			args: args{
				ctx:     errCtx,
				token:   token,
				payload: payload,
			},
			wantErr: protocol.ErrSignatureInvalid,
		},
		{
			name: "inequal payloads",
			args: args{
				ctx:     context.Background(),
				token:   token,
				payload: []byte{0, 1, 2},
			},
			wantErr: protocol.ErrSignatureInvalidPayload,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := new(protocol.TokenClaims)
			err := protocol.CheckSignature(tt.args.ctx, tt.args.token, tt.args.payload, claims, tt.args.supportedSigAlgs, tu.KeySet{})
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckExpiration(t *testing.T) {
	const offset = time.Minute
	tests := []struct {
		name    string
		claims  protocol.Claims
		wantErr error
	}{
		{
			name:    "missing",
			claims:  &protocol.TokenClaims{},
			wantErr: protocol.ErrExpired,
		},
		{
			name: "expired",
			claims: &protocol.TokenClaims{
				Expiration: protocol.FromTime(time.Now().Add(-2 * offset)),
			},
			wantErr: protocol.ErrExpired,
		},
		{
			name: "valid",
			claims: &protocol.TokenClaims{
				Expiration: protocol.FromTime(time.Now().Add(2 * offset)),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.CheckExpiration(tt.claims, offset)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckIssuedAt(t *testing.T) {
	const offset = time.Minute
	tests := []struct {
		name      string
		maxAgeIAT time.Duration
		claims    protocol.Claims
		wantErr   error
	}{
		{
			name:    "missing",
			claims:  &protocol.TokenClaims{},
			wantErr: protocol.ErrIatMissing,
		},
		{
			name: "future",
			claims: &protocol.TokenClaims{
				IssuedAt: protocol.FromTime(time.Now().Add(time.Hour)),
			},
			wantErr: protocol.ErrIatInFuture,
		},
		{
			name: "no max",
			claims: &protocol.TokenClaims{
				IssuedAt: protocol.FromTime(time.Now()),
			},
		},
		{
			name:      "past max",
			maxAgeIAT: time.Minute,
			claims: &protocol.TokenClaims{
				IssuedAt: protocol.FromTime(time.Now().Add(-time.Hour)),
			},
			wantErr: protocol.ErrIatToOld,
		},
		{
			name:      "within max",
			maxAgeIAT: time.Hour,
			claims: &protocol.TokenClaims{
				IssuedAt: protocol.FromTime(time.Now()),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.CheckIssuedAt(tt.claims, tt.maxAgeIAT, offset)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckNonce(t *testing.T) {
	const nonce = "123"
	tests := []struct {
		name    string
		claims  protocol.Claims
		wantErr error
	}{
		{
			name:    "missing",
			claims:  &protocol.TokenClaims{},
			wantErr: protocol.ErrNonceInvalid,
		},
		{
			name: "wrong",
			claims: &protocol.TokenClaims{
				Nonce: "wrong",
			},
			wantErr: protocol.ErrNonceInvalid,
		},
		{
			name: "ok",
			claims: &protocol.TokenClaims{
				Nonce: nonce,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.CheckNonce(tt.claims, nonce)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckAuthorizationContextClassReference(t *testing.T) {
	tests := []struct {
		name    string
		acr     protocol.ACRVerifier
		wantErr error
	}{
		{
			name:    "error",
			acr:     func(s string) error { return errors.New("oops") },
			wantErr: protocol.ErrAcrInvalid,
		},
		{
			name: "ok",
			acr:  func(s string) error { return nil },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.CheckAuthorizationContextClassReference(&protocol.IDTokenClaims{}, tt.acr)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckAuthTime(t *testing.T) {
	tests := []struct {
		name    string
		claims  protocol.Claims
		maxAge  time.Duration
		wantErr error
	}{
		{
			name:   "no max age",
			claims: &protocol.TokenClaims{},
		},
		{
			name:    "missing",
			claims:  &protocol.TokenClaims{},
			maxAge:  time.Minute,
			wantErr: protocol.ErrAuthTimeNotPresent,
		},
		{
			name:   "expired",
			maxAge: time.Minute,
			claims: &protocol.TokenClaims{
				AuthTime: protocol.FromTime(time.Now().Add(-time.Hour)),
			},
			wantErr: protocol.ErrAuthTimeToOld,
		},
		{
			name:   "ok",
			maxAge: time.Minute,
			claims: &protocol.TokenClaims{
				AuthTime: protocol.NowTime(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.CheckAuthTime(tt.claims, tt.maxAge)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}
