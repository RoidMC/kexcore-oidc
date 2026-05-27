package codec

import (
	"fmt"
	"reflect"
	"strconv"
)

// Encode converts src (a struct or pointer to struct) into a map[string][]string
// using "storm" struct tags.
//
// Fields with `storm:",omitempty"` whose zero value is empty will be omitted.
// Custom types can be handled by registering Converters.
func Encode(src any, converters map[reflect.Type]Converter) (map[string][]string, error) {
	v := reflect.ValueOf(src)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("codec: Encode expects struct, got %s", v.Kind())
	}
	return encodeStruct(v, converters)
}

func encodeStruct(v reflect.Value, converters map[reflect.Type]Converter) (map[string][]string, error) {
	result := make(map[string][]string)
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
		fv := v.Field(i)
		omitempty := opts == "omitempty"

		s, valid := fieldToString(fv, omitempty, converters)
		if !valid {
			continue
		}
		result[name] = []string{s}
	}
	return result, nil
}

func fieldToString(fv reflect.Value, omitempty bool, converters map[reflect.Type]Converter) (string, bool) {
	// try registered converter first
	if c, ok := converters[fv.Type()]; ok {
		return c.ToString(fv)
	}
	// pointer unwrap
	if fv.Kind() == reflect.Ptr {
		if fv.IsNil() {
			return "", !omitempty
		}
		fv = fv.Elem()
	}
	switch fv.Kind() {
	case reflect.String:
		s := fv.String()
		if omitempty && s == "" {
			return "", false
		}
		return s, true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := fv.Int()
		if omitempty && n == 0 {
			return "", false
		}
		return strconv.FormatInt(n, 10), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := fv.Uint()
		if omitempty && n == 0 {
			return "", false
		}
		return strconv.FormatUint(n, 10), true
	case reflect.Bool:
		b := fv.Bool()
		if omitempty && !b {
			return "", false
		}
		return strconv.FormatBool(b), true
	case reflect.Float32, reflect.Float64:
		f := fv.Float()
		if omitempty && f == 0 {
			return "", false
		}
		return strconv.FormatFloat(f, 'f', -1, 64), true
	default:
		if fv.Type().Implements(reflect.TypeOf((*interface{ TextMarshaler() ([]byte, error) })(nil)).Elem()) {
			m := fv.MethodByName("MarshalText")
			if m.IsValid() {
				out := m.Call(nil)
				if !out[1].IsNil() {
					return "", false
				}
				return string(out[0].Interface().([]byte)), true
			}
		}
		return "", false
	}
}

// EncodeFlat encodes src and returns a flat "application/x-www-form-urlencoded" string.
// This is a convenience wrapper around Encode.
func EncodeFlat(src any, converters map[reflect.Type]Converter) (string, error) {
	values, err := Encode(src, converters)
	if err != nil {
		return "", err
	}
	form := make(map[string][]string, len(values))
	for k, v := range values {
		form[k] = v
	}
	return encodeURLValues(form), nil
}

func encodeURLValues(form map[string][]string) string {
	// simple implementation: build query string
	var parts []string
	for k, vs := range form {
		for _, v := range vs {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "&"
		}
		result += p
	}
	return result
}

// TextMarshaler is the interface implemented by types that can marshal
// themselves into valid textual representation.
// It mirrors encoding.TextMarshaler without importing encoding.
type TextMarshaler interface {
	MarshalText() ([]byte, error)
}