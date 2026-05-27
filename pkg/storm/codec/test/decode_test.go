package codec_test

import (
	"reflect"
	"testing"

	"github.com/roidmc/kexcore-oidc/pkg/storm/codec"
)

func TestDecode(t *testing.T) {
	type TestStruct struct {
		Name  string `storm:"name"`
		Age   int    `storm:"age"`
		Admin bool   `storm:"admin"`
	}

	tests := []struct {
		name    string
		form    map[string][]string
		want    TestStruct
		wantErr bool
	}{
		{
			name: "basic fields",
			form: map[string][]string{
				"name":  {"alice"},
				"age":   {"30"},
				"admin": {"true"},
			},
			want: TestStruct{Name: "alice", Age: 30, Admin: true},
		},
		{
			name: "missing optional fields",
			form: map[string][]string{
				"name": {"bob"},
			},
			want: TestStruct{Name: "bob"},
		},
		{
			name: "empty form yields zero struct",
			form: map[string][]string{},
			want: TestStruct{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dst TestStruct
			err := codec.Decode(&dst, tt.form, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Decode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if dst != tt.want {
				t.Errorf("Decode() = %+v, want %+v", dst, tt.want)
			}
		})
	}
}

func TestDecodeInvalidInput(t *testing.T) {
	err := codec.Decode(nil, nil, nil)
	if err == nil {
		t.Error("expected error for nil dst")
	}
	err = codec.Decode(new(int), nil, nil)
	if err == nil {
		t.Error("expected error for non-struct")
	}
}

func TestDecodeSkipUnexported(t *testing.T) {
	type outer struct {
		x    int    `storm:"x"`
		Name string `storm:"name"`
	}

	var dst outer
	err := codec.Decode(&dst, map[string][]string{"name": {"test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dst.Name != "test" {
		t.Errorf("Name = %q, want %q", dst.Name, "test")
	}
	if dst.x != 0 {
		t.Errorf("unexported field should be zero: got %d", dst.x)
	}
}

func TestDecodePointerField(t *testing.T) {
	type inner struct {
		MaxAge *uint `storm:"max_age"`
	}
	var dst inner
	err := codec.Decode(&dst, map[string][]string{"max_age": {"300"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dst.MaxAge == nil {
		t.Fatal("MaxAge is nil")
	}
	if *dst.MaxAge != 300 {
		t.Errorf("MaxAge = %d, want 300", *dst.MaxAge)
	}
}

func TestDecodeCustomConverter(t *testing.T) {
	type customScopes string

	converters := map[reflect.Type]codec.Converter{
		reflect.TypeOf(customScopes("")): {
			FromString: func(dst reflect.Value, src string) error {
				dst.SetString(src)
				return nil
			},
			ToString: func(src reflect.Value) (string, bool) {
				s := src.String()
				if s == "" {
					return "", false
				}
				return s, true
			},
		},
	}

	type Custom struct {
		Scopes customScopes `storm:"scope"`
	}

	var dst Custom
	err := codec.Decode(&dst, map[string][]string{"scope": {"openid profile"}}, converters)
	if err != nil {
		t.Fatal(err)
	}
	if string(dst.Scopes) != "openid profile" {
		t.Errorf("Scopes = %q, want %q", dst.Scopes, "openid profile")
	}
}

func TestEncode(t *testing.T) {
	type TestStruct struct {
		Name  string `storm:"name"`
		Age   int    `storm:"age"`
		Admin bool   `storm:"admin,omitempty"`
	}

	tests := []struct {
		name    string
		src     TestStruct
		want    map[string][]string
		wantErr bool
	}{
		{
			name: "all fields",
			src:  TestStruct{Name: "alice", Age: 30, Admin: true},
			want: map[string][]string{
				"name":  {"alice"},
				"age":   {"30"},
				"admin": {"true"},
			},
		},
		{
			name: "omitempty zero bool",
			src:  TestStruct{Name: "bob", Age: 25, Admin: false},
			want: map[string][]string{
				"name": {"bob"},
				"age":  {"25"},
			},
		},
		{
			name: "omitempty zero string",
			src:  TestStruct{Name: "", Age: 0, Admin: false},
			want: map[string][]string{
				"name": {""},
				"age":  {"0"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := codec.Encode(tt.src, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Encode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Errorf("Encode() len = %d, want %d", len(got), len(tt.want))
			}
			for k, v := range tt.want {
				if got[k] == nil || len(got[k]) != len(v) || got[k][0] != v[0] {
					t.Errorf("Encode()[%q] = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	type roundtrip struct {
		Name  string `storm:"name"`
		Age   int    `storm:"age"`
		Admin bool   `storm:"admin"`
	}

	src := roundtrip{Name: "test", Age: 42, Admin: true}
	encoded, err := codec.Encode(src, nil)
	if err != nil {
		t.Fatal(err)
	}

	var dst roundtrip
	err = codec.Decode(&dst, encoded, nil)
	if err != nil {
		t.Fatal(err)
	}

	if dst != src {
		t.Errorf("roundtrip = %+v, want %+v", dst, src)
	}
}
