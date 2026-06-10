package protocol

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type jsonErrorTest struct{}

func (jsonErrorTest) MarshalJSON() ([]byte, error) {
	return nil, errors.New("test")
}

func Test_mergeAndMarshalClaims(t *testing.T) {
	type args struct {
		registered any
		claims     map[string]any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "encoder error",
			args: args{
				registered: jsonErrorTest{},
			},
			wantErr: true,
		},
		{
			name: "no claims",
			args: args{
				registered: struct {
					Foo string `json:"foo,omitempty"`
				}{
					Foo: "bar",
				},
			},
			want: "{\"foo\":\"bar\"}",
		},
		{
			name: "with claims",
			args: args{
				registered: struct {
					Foo string `json:"foo,omitempty"`
				}{
					Foo: "bar",
				},
				claims: map[string]any{
					"bar": "foo",
				},
			},
			want: "{\"bar\":\"foo\",\"foo\":\"bar\"}",
		},
		{
			name: "registered overwrites custom",
			args: args{
				registered: struct {
					Foo string `json:"foo,omitempty"`
				}{
					Foo: "bar",
				},
				claims: map[string]any{
					"foo": "Hello, World!",
				},
			},
			want: "{\"foo\":\"bar\"}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mergeAndMarshalClaims(tt.args.registered, tt.args.claims)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func Test_unmarshalJSONMulti(t *testing.T) {
	type dst struct {
		Foo string `json:"foo,omitempty"`
	}

	type args struct {
		data         string
		destinations []any
	}
	tests := []struct {
		name    string
		args    args
		want    []any
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				data: "~!~~",
				destinations: []any{
					&dst{},
					&map[string]any{},
				},
			},
			want: []any{
				&dst{},
				&map[string]any{},
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				data: "{\"bar\":\"foo\",\"foo\":\"bar\"}\n",
				destinations: []any{
					&dst{},
					&map[string]any{},
				},
			},
			want: []any{
				&dst{Foo: "bar"},
				&map[string]any{
					"foo": "bar",
					"bar": "foo",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := unmarshalJSONMulti([]byte(tt.args.data), tt.args.destinations...)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, tt.args.destinations)
		})
	}
}

func TestNewEncoder(t *testing.T) {
	type request struct {
		Scopes SpaceDelimitedArray `schema:"scope"`
	}
	a := request{
		Scopes: SpaceDelimitedArray{"foo", "bar"},
	}

	values := make(url.Values)
	NewEncoder().Encode(a, values)
	assert.Equal(t, url.Values{"scope": []string{"foo bar"}}, values)

	var b request
	b.Scopes = strings.Split(values.Get("scope"), " ")
	assert.Equal(t, a, b)
}

func Test_parseSchemaTag(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		wantName string
		wantOpts schemaTagOpts
	}{
		{"simple", "foo", "foo", schemaTagOpts{}},
		{"omitempty", "foo,omitempty", "foo", schemaTagOpts{omitempty: true}},
		{"multiple opts", "foo,omitempty,bar", "foo", schemaTagOpts{omitempty: true}},
		{"empty name omitempty", ",omitempty", "", schemaTagOpts{omitempty: true}},
		{"no opts", "foo", "foo", schemaTagOpts{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, opts := parseSchemaTag(tt.tag)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantOpts, opts)
		})
	}
}

func TestEncoder_Encode_errors(t *testing.T) {
	e := NewEncoder()
	err := e.Encode("not a struct", make(url.Values))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expects struct")

	err = e.Encode(42, make(url.Values))
	require.Error(t, err)
}

func TestEncoder_Encode_omitempty(t *testing.T) {
	type req struct {
		A string `schema:"a"`
		B string `schema:"b,omitempty"`
	}
	values := make(url.Values)
	require.NoError(t, NewEncoder().Encode(req{A: "x", B: ""}, values))
	assert.Equal(t, url.Values{"a": []string{"x"}}, values)
}

func TestEncoder_Encode_pointer(t *testing.T) {
	type req struct {
		A *string `schema:"a,omitempty"`
	}
	values := make(url.Values)
	require.NoError(t, NewEncoder().Encode(req{A: nil}, values))
	assert.Empty(t, values)

	s := "hello"
	values = make(url.Values)
	require.NoError(t, NewEncoder().Encode(req{A: &s}, values))
	assert.Equal(t, url.Values{"a": []string{"hello"}}, values)
}

func TestEncoder_Encode_types(t *testing.T) {
	type req struct {
		S  string  `schema:"s"`
		I  int     `schema:"i"`
		U  uint    `schema:"u"`
		B  bool    `schema:"b"`
		F  float64 `schema:"f"`
		I8 int8    `schema:"i8"`
	}
	values := make(url.Values)
	require.NoError(t, NewEncoder().Encode(req{S: "x", I: -1, U: 2, B: true, F: 3.14, I8: 8}, values))
	assert.Equal(t, url.Values{
		"s":  []string{"x"},
		"i":  []string{"-1"},
		"u":  []string{"2"},
		"b":  []string{"true"},
		"f":  []string{"3.140000"},
		"i8": []string{"8"},
	}, values)
}

type textMarshaler struct {
	Value string
}

func (tm textMarshaler) MarshalText() ([]byte, error) {
	return []byte("marshaled:" + tm.Value), nil
}

func TestEncoder_Encode_TextMarshaler(t *testing.T) {
	type req struct {
		TM textMarshaler `schema:"tm"`
	}
	values := make(url.Values)
	require.NoError(t, NewEncoder().Encode(req{TM: textMarshaler{Value: "test"}}, values))
	assert.Equal(t, url.Values{"tm": []string{"marshaled:test"}}, values)
}

func TestEncoder_Encode_unexported(t *testing.T) {
	// unexported field should be skipped by Encode
	type req struct {
		Exported   string `schema:"exported"`
		unexported string `schema:"unexported"`
	}
	values := make(url.Values)
	require.NoError(t, NewEncoder().Encode(req{Exported: "x", unexported: "y"}, values))
	assert.Equal(t, url.Values{"exported": []string{"x"}}, values)
}

func TestDecoder_Decode_errors(t *testing.T) {
	d := NewDecoder()
	err := d.Decode(nil, map[string][]string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-nil pointer")

	var s string
	err = d.Decode(&s, map[string][]string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pointer to struct")
}

func TestDecoder_Decode_unknownKeys(t *testing.T) {
	type req struct {
		A string `schema:"a"`
	}
	var r req
	d := NewDecoder()
	err := d.Decode(&r, map[string][]string{"unknown": []string{"x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key")

	// per-decode option: WithIgnoreUnknownKeys
	err = d.Decode(&r, map[string][]string{"unknown": []string{"x"}}, WithIgnoreUnknownKeys())
	require.NoError(t, err)
}

func TestDecoder_Decode_types(t *testing.T) {
	type req struct {
		S  string  `schema:"s"`
		I  int     `schema:"i"`
		U  uint    `schema:"u"`
		B  bool    `schema:"b"`
		F  float64 `schema:"f"`
		I8 int8    `schema:"i8"`
	}
	var r req
	require.NoError(t, NewDecoder().Decode(&r, map[string][]string{
		"s":  []string{"x"},
		"i":  []string{"-1"},
		"u":  []string{"2"},
		"b":  []string{"true"},
		"f":  []string{"3.14"},
		"i8": []string{"8"},
	}))
	assert.Equal(t, req{S: "x", I: -1, U: 2, B: true, F: 3.14, I8: 8}, r)
}

func TestDecoder_Decode_pointer(t *testing.T) {
	type req struct {
		A *string `schema:"a"`
	}
	var r req
	require.NoError(t, NewDecoder().Decode(&r, map[string][]string{"a": []string{"hello"}}))
	require.NotNil(t, r.A)
	assert.Equal(t, "hello", *r.A)
}

func TestDecoder_Decode_slice(t *testing.T) {
	type req struct {
		S []string `schema:"s"`
	}
	var r req
	require.NoError(t, NewDecoder().Decode(&r, map[string][]string{"s": []string{"a b c"}}))
	assert.Equal(t, []string{"a", "b", "c"}, r.S)
}

type textUnmarshaler struct {
	Value string
}

func (tu *textUnmarshaler) UnmarshalText(text []byte) error {
	tu.Value = "unmarshaled:" + string(text)
	return nil
}

func TestDecoder_Decode_TextUnmarshaler(t *testing.T) {
	type req struct {
		TU textUnmarshaler `schema:"tu"`
	}
	var r req
	require.NoError(t, NewDecoder().Decode(&r, map[string][]string{"tu": []string{"test"}}))
	assert.Equal(t, "unmarshaled:test", r.TU.Value)
}

func TestDecoder_RegisterParser(t *testing.T) {
	type customType struct {
		V string
	}
	d := NewDecoder()
	d.RegisterParser(reflect.TypeOf(customType{}), func(s string) (reflect.Value, error) {
		return reflect.ValueOf(customType{V: "custom:" + s}), nil
	})

	type req struct {
		C customType `schema:"c"`
	}
	var r req
	require.NoError(t, d.Decode(&r, map[string][]string{"c": []string{"test"}}))
	assert.Equal(t, "custom:test", r.C.V)
}

func TestDecoder_Decode_emptyValues(t *testing.T) {
	type req struct {
		A string `schema:"a"`
	}
	var r req
	require.NoError(t, NewDecoder().Decode(&r, map[string][]string{"a": []string{}}))
	assert.Equal(t, "", r.A)
}

func TestDecoder_Decode_unsupportedSlice(t *testing.T) {
	type req struct {
		I []int `schema:"i"`
	}
	var r req
	err := NewDecoder().Decode(&r, map[string][]string{"i": []string{"1 2"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported slice type")
}

func TestDecoder_Decode_unsupportedType(t *testing.T) {
	type req struct {
		M map[string]string `schema:"m"`
	}
	var r req
	err := NewDecoder().Decode(&r, map[string][]string{"m": []string{"x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported field type")
}

func TestDecoder_Decode_invalidInt(t *testing.T) {
	type req struct {
		I int `schema:"i"`
	}
	var r req
	err := NewDecoder().Decode(&r, map[string][]string{"i": []string{"not-a-number"}})
	require.Error(t, err)
}

func TestDecoder_Decode_invalidBool(t *testing.T) {
	type req struct {
		B bool `schema:"b"`
	}
	var r req
	err := NewDecoder().Decode(&r, map[string][]string{"b": []string{"not-a-bool"}})
	require.Error(t, err)
}

func TestDecoder_Decode_invalidFloat(t *testing.T) {
	type req struct {
		F float64 `schema:"f"`
	}
	var r req
	err := NewDecoder().Decode(&r, map[string][]string{"f": []string{"not-a-float"}})
	require.Error(t, err)
}
