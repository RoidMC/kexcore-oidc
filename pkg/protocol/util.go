package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// mergeAndMarshalClaims merges registered and the custom
// claims map into a single JSON object.
// Registered fields overwrite custom claims.
func mergeAndMarshalClaims(registered any, extraClaims map[string]any) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := json.NewEncoder(buf).Encode(registered); err != nil {
		return nil, fmt.Errorf("protocol registered claims: %w", err)
	}

	if len(extraClaims) > 0 {
		merged := make(map[string]any)
		for k, v := range extraClaims {
			merged[k] = v
		}

		if err := json.NewDecoder(buf).Decode(&merged); err != nil {
			return nil, fmt.Errorf("protocol registered claims: %w", err)
		}

		if err := json.NewEncoder(buf).Encode(merged); err != nil {
			return nil, fmt.Errorf("protocol custom claims: %w", err)
		}
	}

	return buf.Bytes(), nil
}

// unmarshalJSONMulti unmarshals the same JSON data into multiple destinations.
// Each destination must be a pointer, as per json.Unmarshal rules.
func unmarshalJSONMulti(data []byte, destinations ...any) error {
	for _, dst := range destinations {
		if err := json.Unmarshal(data, dst); err != nil {
			return fmt.Errorf("protocol: %w into %T", err, dst)
		}
	}
	return nil
}

// NewEncoder returns an Encoder that knows how to encode
// SpaceDelimitedArray and Locales values into url.Values.
// It replaces the former schema.Encoder dependency.
func NewEncoder() *Encoder {
	return &Encoder{
		customEncoders: map[reflect.Type]func(reflect.Value) string{
			reflect.TypeOf(SpaceDelimitedArray{}): func(v reflect.Value) string {
				return v.Interface().(SpaceDelimitedArray).String()
			},
			reflect.TypeOf(Locales{}): func(v reflect.Value) string {
				return v.Interface().(Locales).String()
			},
		},
	}
}

// Encoder encodes structs into url.Values using "schema" struct tags.
// It is a lightweight replacement for github.com/zitadel/schema.Encoder.
type Encoder struct {
	customEncoders map[reflect.Type]func(reflect.Value) string
}

// Encode encodes src (a struct or pointer to struct) into dst.
// It reads "schema" struct tags for field names.
func (e *Encoder) Encode(src any, dst map[string][]string) error {
	v := reflect.ValueOf(src)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("protocol: Encode expects struct, got %s", v.Kind())
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		tag, ok := field.Tag.Lookup("schema")
		if !ok || tag == "" || tag == "-" {
			continue
		}
		name := tag
		if idx := strings.Index(name, ","); idx >= 0 {
			name = name[:idx]
		}
		fv := v.Field(i)
		s := e.fieldToString(fv)
		if s != "" {
			dst[name] = []string{s}
		}
	}
	return nil
}

func (e *Encoder) fieldToString(fv reflect.Value) string {
	if enc, ok := e.customEncoders[fv.Type()]; ok {
		return enc(fv)
	}
	if fv.Kind() == reflect.Ptr {
		if fv.IsNil() {
			return ""
		}
		fv = fv.Elem()
	}
	switch fv.Kind() {
	case reflect.String:
		return fv.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%d", fv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%d", fv.Uint())
	case reflect.Bool:
		return fmt.Sprintf("%t", fv.Bool())
	case reflect.Float32, reflect.Float64:
		return fmt.Sprintf("%f", fv.Float())
	default:
		return fmt.Sprintf("%v", fv.Interface())
	}
}
