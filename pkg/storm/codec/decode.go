// Package codec provides form ↔ struct encoding and decoding
// using "storm" struct tags, replacing the external zitadel/schema dependency.
//
// Decoder: map[string][]string (HTTP form values) → Go struct
// Encoder: Go struct → map[string][]string (HTTP form values)
//
// Tag format: `storm:"field_name,omitempty"`
// Only the first value from []string is used for decoding.
package codec

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Converter maps a custom type's string representation to/from a reflect.Value.
// Register converters for types that can't be handled by the default decoder
// (e.g., SpaceDelimitedArray, Locales, ResponseType).
type Converter struct {
	// FromString converts a string into the target type.
	// The dst Value is settable.
	FromString func(dst reflect.Value, src string) error
	// ToString converts the source value to its string representation.
	// Returns ("", false) if the value should be treated as empty/omitted.
	ToString func(src reflect.Value) (string, bool)
}

// Decode populates dst (a pointer to a struct) from form values
// using "storm" struct tags.
//
// The dst parameter must be a non-nil pointer to a struct.
// Unknown fields in the form are silently ignored.
// Custom types can be handled by registering Converters.
func Decode(dst any, form map[string][]string, converters map[reflect.Type]Converter) error {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("codec: Decode expects non-nil pointer to struct, got %T", dst)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("codec: Decode expects pointer to struct, got pointer to %s", v.Kind())
	}
	return decodeStruct(v, form, converters)
}

func decodeStruct(v reflect.Value, form map[string][]string, converters map[reflect.Type]Converter) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		tag, ok := field.Tag.Lookup("storm")
		if !ok || tag == "" {
			continue
		}
		name, opts := parseTag(tag)
		values, exists := form[name]
		if !exists || len(values) == 0 {
			continue
		}
		fv := v.Field(i)
		if err := setField(fv, values[0], converters); err != nil {
			return fmt.Errorf("codec: field %q: %w", name, err)
		}
		// mark used
		_ = opts
	}
	return nil
}

func parseTag(tag string) (name string, opts string) {
	if idx := strings.Index(tag, ","); idx != -1 {
		return tag[:idx], tag[idx+1:]
	}
	return tag, ""
}

func setField(fv reflect.Value, s string, converters map[reflect.Type]Converter) error {
	if s == "" && !isStringKind(fv.Kind()) {
		return nil
	}
	// try registered converter first
	if c, ok := converters[fv.Type()]; ok {
		return c.FromString(fv, s)
	}
	// pointer unwrap
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
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid int: %s", s)
		}
		fv.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid uint: %s", s)
		}
		fv.SetUint(n)
	case reflect.Bool:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return fmt.Errorf("invalid bool: %s", s)
		}
		fv.SetBool(b)
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fmt.Errorf("invalid float: %s", s)
		}
		fv.SetFloat(f)
	default:
		if fv.Type().Implements(reflect.TypeOf((*interface{ UnmarshalText([]byte) error })(nil)).Elem()) {
			m := fv.MethodByName("UnmarshalText")
			if m.IsValid() {
				out := m.Call([]reflect.Value{reflect.ValueOf([]byte(s))})
				if !out[0].IsNil() {
					return out[0].Interface().(error)
				}
				return nil
			}
		}
		return fmt.Errorf("unsupported type %s", fv.Type())
	}
	return nil
}

func isStringKind(k reflect.Kind) bool {
	return k == reflect.String
}
