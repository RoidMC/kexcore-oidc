package protocol

import (
	"encoding"
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

// schemaTagOpts holds parsed options from a "schema" struct tag.
type schemaTagOpts struct {
	omitempty bool
}

// parseSchemaTag parses a schema tag like "name" or "name,omitempty".
// It returns the field name and any options.
func parseSchemaTag(tag string) (string, schemaTagOpts) {
	var opts schemaTagOpts
	if idx := strings.Index(tag, ","); idx >= 0 {
		for _, opt := range strings.Split(tag[idx+1:], ",") {
			if opt == "omitempty" {
				opts.omitempty = true
			}
		}
		return tag[:idx], opts
	}
	return tag, opts
}

// NewEncoder returns an Encoder that knows how to encode
// SpaceDelimitedArray and Locales values into url.Values.
func NewEncoder() *Encoder {
	return &Encoder{
		customEncoders: map[reflect.Type]func(reflect.Value) (string, bool){
			reflect.TypeOf(SpaceDelimitedArray{}): func(v reflect.Value) (string, bool) {
				s := v.Interface().(SpaceDelimitedArray).String()
				return s, s != ""
			},
			reflect.TypeOf(Locales{}): func(v reflect.Value) (string, bool) {
				s := v.Interface().(Locales).String()
				return s, s != ""
			},
		},
	}
}

// Encoder encodes structs into url.Values using "schema" struct tags.
// It replaces the former github.com/zitadel/schema.Encoder dependency.
type Encoder struct {
	customEncoders map[reflect.Type]func(reflect.Value) (string, bool)
}

// Encode encodes src (a struct or pointer to struct) into dst.
// It reads "schema" struct tags for field names.
// Fields with `schema:",omitempty"` whose zero value is empty will be omitted.
// Custom types implementing encoding.TextMarshaler are supported.
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
		name, opts := parseSchemaTag(tag)
		fv := v.Field(i)
		s, valid := e.fieldToString(fv, opts.omitempty)
		if !valid {
			continue
		}
		dst[name] = []string{s}
	}
	return nil
}

func (e *Encoder) fieldToString(fv reflect.Value, omitempty bool) (string, bool) {
	if enc, ok := e.customEncoders[fv.Type()]; ok {
		return enc(fv)
	}
	if m, ok := fv.Interface().(encoding.TextMarshaler); ok {
		b, err := m.MarshalText()
		if err != nil {
			return "", false
		}
		s := string(b)
		if omitempty && s == "" {
			return "", false
		}
		return s, true
	}
	if fv.Kind() == reflect.Ptr {
		if fv.IsNil() {
			if omitempty {
				return "", false
			}
			return "", true
		}
		fv = fv.Elem()
	}
	if omitempty && fv.IsZero() {
		return "", false
	}
	switch fv.Kind() {
	case reflect.String:
		return fv.String(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%d", fv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%d", fv.Uint()), true
	case reflect.Bool:
		return fmt.Sprintf("%t", fv.Bool()), true
	case reflect.Float32, reflect.Float64:
		return fmt.Sprintf("%f", fv.Float()), true
	default:
		return fmt.Sprintf("%v", fv.Interface()), true
	}
}

// NewDecoder returns a Decoder that knows how to decode
// SpaceDelimitedArray and Locales values from url.Values.
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
// It replaces the former github.com/zitadel/schema.Decoder dependency.
type Decoder struct {
	ignoreUnknownKeys bool
	customParsers     map[reflect.Type]func(string) (reflect.Value, error)
}

// DecodeOption configures per-decode behavior.
type DecodeOption func(*decodeConfig)

type decodeConfig struct {
	ignoreUnknownKeys bool
}

// WithIgnoreUnknownKeys returns a DecodeOption that causes the decoder to
// skip keys that do not match any exported field with a "schema" tag.
// Use this when the source map may contain fields not in the target struct
// (e.g., client authentication fields in PAR requests).
func WithIgnoreUnknownKeys() DecodeOption {
	return func(c *decodeConfig) {
		c.ignoreUnknownKeys = true
	}
}

// RegisterParser registers a custom string parser for a specific reflect.Type.
// It is used by StormEngine plugins to handle non-standard field types.
func (d *Decoder) RegisterParser(rt reflect.Type, parser func(string) (reflect.Value, error)) {
	d.customParsers[rt] = parser
}

// Decode decodes src (map[string][]string) into dst (struct pointer).
// It reads "schema" struct tags for field names.
// Custom types implementing encoding.TextUnmarshaler are supported.
//
// Options can be passed to override per-decode behavior:
//
//	decoder.Decode(authReq, r.Form, protocol.WithIgnoreUnknownKeys())
func (d *Decoder) Decode(dst any, src map[string][]string, opts ...DecodeOption) error {
	cfg := &decodeConfig{ignoreUnknownKeys: d.ignoreUnknownKeys}
	for _, opt := range opts {
		opt(cfg)
	}

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
		name, _ := parseSchemaTag(tag)
		fieldMap[name] = i
	}

	for key, values := range src {
		idx, ok := fieldMap[key]
		if !ok {
			if cfg.ignoreUnknownKeys {
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
		if u, ok := fv.Addr().Interface().(encoding.TextUnmarshaler); ok {
			return u.UnmarshalText([]byte(s))
		}
		return fmt.Errorf("protocol: unsupported field type %s", fv.Type())
	}
	return nil
}
