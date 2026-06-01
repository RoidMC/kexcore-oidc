package protocol

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// mergeAndMarshalClaims merges registered and the custom
// claims map into a single JSON object.
// Registered fields overwrite custom claims.
func mergeAndMarshalClaims(registered any, extraClaims map[string]any) ([]byte, error) {
	registeredJSON, err := json.Marshal(registered)
	if err != nil {
		return nil, fmt.Errorf("protocol registered claims: %w", err)
	}

	if len(extraClaims) == 0 {
		return registeredJSON, nil
	}

	merged := make(map[string]any)
	for k, v := range extraClaims {
		merged[k] = v
	}

	if err := json.Unmarshal(registeredJSON, &merged); err != nil {
		return nil, fmt.Errorf("protocol registered claims: %w", err)
	}

	out, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("protocol custom claims: %w", err)
	}
	return out, nil
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

// NewDecoder returns a Decoder that knows how to decode
// SpaceDelimitedArray and Locales values from url.Values.
// It replaces the former schema.Decoder dependency.
func NewDecoder() *Decoder {
	return &Decoder{
		customParsers: map[reflect.Type]func(string) (reflect.Value, error){
			reflect.TypeOf(SpaceDelimitedArray{}): func(s string) (reflect.Value, error) {
				return reflect.ValueOf(SpaceDelimitedArray(strings.Fields(s))), nil
			},
			reflect.TypeOf(Locales{}): func(s string) (reflect.Value, error) {
				return reflect.ValueOf(ParseLocales(strings.Fields(s))), nil
			},
		},
	}
}

// Decoder decodes url.Values into structs using "schema" struct tags.
// It is a lightweight replacement for github.com/zitadel/schema.Decoder.
type Decoder struct {
	ignoreUnknownKeys bool
	customParsers     map[reflect.Type]func(string) (reflect.Value, error)
}

// IgnoreUnknownKeys configures the decoder to skip keys that do not
// match any exported field with a "schema" tag.
func (d *Decoder) IgnoreUnknownKeys(ignore bool) {
	d.ignoreUnknownKeys = ignore
}

// Decode decodes src (map[string][]string) into dst (struct pointer).
// It reads "schema" struct tags for field names.
func (d *Decoder) Decode(dst any, src map[string][]string) error {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("protocol: Decode expects non-nil pointer, got %T", dst)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("protocol: Decode expects pointer to struct, got %T", dst)
	}
	t := v.Type()

	// Build schema tag → field index map
	fieldMap := make(map[string]int)
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
		fieldMap[name] = i
	}

	for key, values := range src {
		idx, ok := fieldMap[key]
		if !ok {
			if d.ignoreUnknownKeys {
				continue
			}
			return fmt.Errorf("protocol: unknown key %q", key)
		}
		if len(values) == 0 {
			continue
		}
		fv := v.Field(idx)
		if err := d.setField(fv, values[0]); err != nil {
			return fmt.Errorf("protocol: decode %q: %w", key, err)
		}
	}
	return nil
}

func (d *Decoder) setField(fv reflect.Value, s string) error {
	if parser, ok := d.customParsers[fv.Type()]; ok {
		parsed, err := parser(s)
		if err != nil {
			return err
		}
		fv.Set(parsed)
		return nil
	}
	if fv.Kind() == reflect.Ptr {
		if fv.IsNil() {
			fv.Set(reflect.New(fv.Type().Elem()))
		}
		fv = fv.Elem()
	}
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(s)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		fv.SetInt(i)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		i, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		fv.SetUint(i)
	case reflect.Bool:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return err
		}
		fv.SetBool(b)
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return err
		}
		fv.SetFloat(f)
	case reflect.Slice:
		if fv.Type().Elem().Kind() == reflect.String {
			fv.Set(reflect.ValueOf(strings.Fields(s)))
			return nil
		}
		return fmt.Errorf("protocol: unsupported slice type %s", fv.Type())
	default:
		return fmt.Errorf("protocol: unsupported field type %s", fv.Type())
	}
	return nil
}
