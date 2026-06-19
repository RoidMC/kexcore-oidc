// Tests migrated from oidc/types_test.go

package protocol_test

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

// ============================================================================
// Audience
// ============================================================================

func TestAudience_UnmarshalText(t *testing.T) {
	type args struct {
		text []byte
	}
	type res struct {
		audience protocol.Audience
	}
	tests := []struct {
		name    string
		args    args
		res     res
		wantErr bool
	}{
		{
			"invalid value",
			args{
				[]byte(`{"aud": {"a": }}}`),
			},
			res{},
			true,
		},
		{
			"single audience",
			args{
				[]byte(`{"aud": "single audience"}`),
			},
			res{
				[]string{"single audience"},
			},
			false,
		},
		{
			"multiple audience",
			args{
				[]byte(`{"aud": ["multiple", "audience"]}`),
			},
			res{
				[]string{"multiple", "audience"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := new(struct {
				Audience protocol.Audience `json:"aud"`
			})
			if err := json.Unmarshal(tt.args.text, &a); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.ElementsMatch(t, a.Audience, tt.res.audience)
		})
	}
}

// ============================================================================
// AuthenticationMethodsReferences
// ============================================================================

func TestAuthenticationMethodsReferences_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    protocol.AuthenticationMethodsReferences
		wantErr bool
	}{
		{
			name:  "single auth method",
			input: `{"amr":"pwd"}`,
			want:  protocol.AuthenticationMethodsReferences{"pwd"},
		},
		{
			name:  "multiple auth methods",
			input: `{"amr":["pwd","mfa"]}`,
			want:  protocol.AuthenticationMethodsReferences{"pwd", "mfa"},
		},
		{
			name:  "null",
			input: `{"amr":null}`,
		},
		{
			name:    "invalid type",
			input:   `{"amr":1}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got struct {
				AMR protocol.AuthenticationMethodsReferences `json:"amr,omitempty"`
			}
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.AMR)
		})
	}
}

// ============================================================================
// Display
// ============================================================================

func TestDisplay_UnmarshalText(t *testing.T) {
	type args struct {
		text []byte
	}
	type res struct {
		display protocol.Display
	}
	tests := []struct {
		name    string
		args    args
		res     res
		wantErr bool
	}{
		{
			"unknown value",
			args{
				[]byte("unknown"),
			},
			res{},
			false,
		},
		{
			"page",
			args{
				[]byte("page"),
			},
			res{protocol.Display("page")},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d protocol.Display
			if err := d.UnmarshalText(tt.args.text); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			if d != tt.res.display {
				t.Errorf("Display is not correct is = %v, want %v", d, tt.res.display)
			}
		})
	}
}

// ============================================================================
// Locale
// ============================================================================

func TestLocale_Tag(t *testing.T) {
	tests := []struct {
		name string
		l    *protocol.Locale
		want language.Tag
	}{
		{
			name: "nil",
			l:    nil,
			want: language.Und,
		},
		{
			name: "Und",
			l:    protocol.NewLocale(language.Und),
			want: language.Und,
		},
		{
			name: "language",
			l:    protocol.NewLocale(language.Afrikaans),
			want: language.Afrikaans,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.l.Tag())
		})
	}
}

func TestLocale_String(t *testing.T) {
	tests := []struct {
		name string
		l    *protocol.Locale
		want language.Tag
	}{
		{
			name: "nil",
			l:    nil,
			want: language.Und,
		},
		{
			name: "Und",
			l:    protocol.NewLocale(language.Und),
			want: language.Und,
		},
		{
			name: "language",
			l:    protocol.NewLocale(language.Afrikaans),
			want: language.Afrikaans,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want.String(), tt.l.String())
		})
	}
}

func TestLocale_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		l       *protocol.Locale
		want    string
		wantErr bool
	}{
		{
			name: "nil",
			l:    nil,
			want: "null",
		},
		{
			name: "und",
			l:    protocol.NewLocale(language.Und),
			want: "null",
		},
		{
			name: "language",
			l:    protocol.NewLocale(language.Afrikaans),
			want: `"af"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.l)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestLocale_UnmarshalJSON(t *testing.T) {
	type dst struct {
		Locale *protocol.Locale `json:"locale,omitempty"`
	}
	tests := []struct {
		name    string
		input   string
		want    dst
		wantErr bool
	}{
		{
			name:    "value not present",
			input:   `{}`,
			wantErr: false,
			want: dst{
				Locale: nil,
			},
		},
		{
			name:    "null",
			input:   `{"locale": null}`,
			wantErr: false,
			want: dst{
				Locale: nil,
			},
		},
		{
			name:    "empty, ignored",
			input:   `{"locale": ""}`,
			wantErr: false,
			want: dst{
				Locale: &protocol.Locale{},
			},
		},
		{
			name:  "afrikaans, ok",
			input: `{"locale": "af"}`,
			want: dst{
				Locale: protocol.NewLocale(language.Afrikaans),
			},
		},
		{
			name:  "gb, ignored",
			input: `{"locale": "gb"}`,
			want: dst{
				Locale: &protocol.Locale{},
			},
		},
		{
			name:    "bad form, error",
			input:   `{"locale": "g!!!!!"}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got dst
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// Locales
// ============================================================================

func TestParseLocales(t *testing.T) {
	in := []string{language.Afrikaans.String(), language.Danish.String(), "foobar", language.Und.String()}
	want := protocol.Locales{language.Afrikaans, language.Danish}
	got := protocol.ParseLocales(in)
	assert.ElementsMatch(t, want, got)
}

func TestLocales_UnmarshalText(t *testing.T) {
	type args struct {
		text []byte
	}
	type res struct {
		tags []language.Tag
	}
	tests := []struct {
		name    string
		args    args
		res     res
		wantErr bool
	}{
		{
			"unknown value",
			args{
				[]byte("unknown"),
			},
			res{},
			false,
		},
		{
			"undefined",
			args{
				[]byte("und"),
			},
			res{},
			false,
		},
		{
			"single language",
			args{
				[]byte("de"),
			},
			res{[]language.Tag{language.German}},
			false,
		},
		{
			"multiple languages",
			args{
				[]byte("de en"),
			},
			res{[]language.Tag{language.German, language.English}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var locales protocol.Locales
			if err := locales.UnmarshalText(tt.args.text); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.ElementsMatch(t, locales, tt.res.tags)
		})
	}
}

func TestLocales_UnmarshalJSON(t *testing.T) {
	in := []string{language.Afrikaans.String(), language.Danish.String(), "foobar", language.Und.String()}
	spaceSepStr := strconv.Quote(strings.Join(in, " "))
	jsonArray, err := json.Marshal(in)
	require.NoError(t, err)

	out := protocol.Locales{language.Afrikaans, language.Danish}

	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    protocol.Locales
		wantErr bool
	}{
		{
			name: "invalid JSON",
			args: args{
				data: []byte("~~~"),
			},
			wantErr: true,
		},
		{
			name: "null",
			args: args{
				data: []byte("null"),
			},
			want: nil,
		},
		{
			name: "space separated string",
			args: args{
				data: []byte(spaceSepStr),
			},
			want: out,
		},
		{
			name: "json string array",
			args: args{
				data: jsonArray,
			},
			want: out,
		},
		{
			name: "json invalid array",
			args: args{
				data: []byte(`[1,2,3]`),
			},
			wantErr: true,
		},
		{
			name: "invalid type (float64)",
			args: args{
				data: []byte("22"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got protocol.Locales
			err := got.UnmarshalJSON([]byte(tt.args.data))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// SpaceDelimitedArray (Scopes)
// ============================================================================

func TestScopes_UnmarshalText(t *testing.T) {
	type args struct {
		text []byte
	}
	type res struct {
		scopes []string
	}
	tests := []struct {
		name    string
		args    args
		res     res
		wantErr bool
	}{
		{
			"unknown value",
			args{
				[]byte("unknown"),
			},
			res{
				[]string{"unknown"},
			},
			false,
		},
		{
			"struct",
			args{
				[]byte(`{"unknown":"value"}`),
			},
			res{
				[]string{`{"unknown":"value"}`},
			},
			false,
		},
		{
			"openid",
			args{
				[]byte("openid"),
			},
			res{
				[]string{"openid"},
			},
			false,
		},
		{
			"multiple scopes",
			args{
				[]byte("openid email custom:scope"),
			},
			res{
				[]string{"openid", "email", "custom:scope"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scopes protocol.SpaceDelimitedArray
			if err := scopes.UnmarshalText(tt.args.text); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.ElementsMatch(t, scopes, tt.res.scopes)
		})
	}
}

func TestScopes_MarshalText(t *testing.T) {
	type args struct {
		scopes protocol.SpaceDelimitedArray
	}
	type res struct {
		scopes []byte
	}
	tests := []struct {
		name    string
		args    args
		res     res
		wantErr bool
	}{
		{
			"unknown value",
			args{
				protocol.SpaceDelimitedArray{"unknown"},
			},
			res{
				[]byte("unknown"),
			},
			false,
		},
		{
			"struct",
			args{
				protocol.SpaceDelimitedArray{`{"unknown":"value"}`},
			},
			res{
				[]byte(`{"unknown":"value"}`),
			},
			false,
		},
		{
			"openid",
			args{
				protocol.SpaceDelimitedArray{"openid"},
			},
			res{
				[]byte("openid"),
			},
			false,
		},
		{
			"multiple scopes",
			args{
				protocol.SpaceDelimitedArray{"openid", "email", "custom:scope"},
			},
			res{
				[]byte("openid email custom:scope"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, err := tt.args.scopes.MarshalText()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(text, tt.res.scopes) {
				t.Errorf("MarshalText() is = %q, want %q", text, tt.res.scopes)
			}
		})
	}
}

func TestSpaceDelimitatedArray_ValuerNotNil(t *testing.T) {
	inputs := [][]string{
		{"two", "elements"},
		{"one"},
		{ /*zero*/ },
	}
	for _, input := range inputs {
		t.Run(strconv.Itoa(len(input))+strings.Join(input, "_"), func(t *testing.T) {
			sda := protocol.SpaceDelimitedArray(input)
			dbValue, err := sda.Value()
			if !assert.NoError(t, err, "Value") {
				return
			}
			var reversed protocol.SpaceDelimitedArray
			err = reversed.Scan(dbValue)
			if assert.NoError(t, err, "Scan string") {
				assert.Equal(t, sda, reversed, "scan string")
			}
			reversed = nil
			dbValueString, ok := dbValue.(string)
			if assert.True(t, ok, "dbValue is string") {
				err = reversed.Scan([]byte(dbValueString))
				if assert.NoError(t, err, "Scan bytes") {
					assert.Equal(t, sda, reversed, "scan bytes")
				}
			}
		})
	}
}

func TestSpaceDelimitatedArray_ValuerNil(t *testing.T) {
	var reversed protocol.SpaceDelimitedArray
	err := reversed.Scan(nil)
	if assert.NoError(t, err, "Scan nil") {
		assert.Equal(t, protocol.SpaceDelimitedArray(nil), reversed, "scan nil")
	}
}

// ============================================================================
// Time
// ============================================================================

func TestTime_AsTime(t *testing.T) {
	tests := []struct {
		name string
		ts   protocol.Time
		want time.Time
	}{
		{
			name: "unset",
			ts:   0,
			want: time.Time{},
		},
		{
			name: "set",
			ts:   1,
			want: time.Unix(1, 0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ts.AsTime()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTime_FromTime(t *testing.T) {
	tests := []struct {
		name string
		tt   time.Time
		want protocol.Time
	}{
		{
			name: "zero",
			tt:   time.Time{},
			want: 0,
		},
		{
			name: "set",
			tt:   time.Unix(1, 0),
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.FromTime(tt.tt)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTime_UnmarshalJSON(t *testing.T) {
	type dst struct {
		UpdatedAt protocol.Time `json:"updated_at"`
	}
	tests := []struct {
		name    string
		json    string
		want    dst
		wantErr bool
	}{
		{
			name: "RFC3339", // https://github.com/zitadel/oidc/issues/292
			json: `{"updated_at": "2021-05-11T21:13:25.566Z"}`,
			want: dst{UpdatedAt: 1620767605},
		},
		{
			name: "int",
			json: `{"updated_at":1620767605}`,
			want: dst{UpdatedAt: 1620767605},
		},
		{
			name:    "time parse error",
			json:    `{"updated_at":"foo"}`,
			wantErr: true,
		},
		{
			name: "null",
			json: `{"updated_at":null}`,
		},
		{
			name:    "invalid type",
			json:    `{"updated_at":["foo","bar"]}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got dst
			err := json.Unmarshal([]byte(tt.json), &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
	t.Run("syntax error", func(t *testing.T) {
		var ts protocol.Time
		err := ts.UnmarshalJSON([]byte{'~'})
		assert.Error(t, err)
	})
}
