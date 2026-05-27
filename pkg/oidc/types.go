// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package oidc

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/muhlemmer/gu"
	"golang.org/x/text/language"
)

type Audience []string

func (a *Audience) UnmarshalJSON(text []byte) error {
	var i any
	err := json.Unmarshal(text, &i)
	if err != nil {
		return err
	}
	switch aud := i.(type) {
	case []any:
		*a = make([]string, len(aud))
		for i, audience := range aud {
			(*a)[i] = audience.(string)
		}
	case string:
		*a = []string{aud}
	}
	return nil
}

type AuthenticationMethodsReferences []string

func (a *AuthenticationMethodsReferences) UnmarshalJSON(data []byte) error {
	var dst any
	if err := json.Unmarshal(data, &dst); err != nil {
		return fmt.Errorf("oidc amr: %w", err)
	}

	switch v := dst.(type) {
	case nil:
		*a = nil
	case string:
		*a = AuthenticationMethodsReferences{v}
	case []any:
		refs, err := gu.AssertInterfaces[string](v)
		if err != nil {
			return fmt.Errorf("oidc amr: %w", err)
		}
		*a = AuthenticationMethodsReferences(refs)
	default:
		return fmt.Errorf("oidc amr: unsupported type: %T", v)
	}
	return nil
}

type Display string

func (d *Display) UnmarshalText(text []byte) error {
	display := Display(text)
	switch display {
	case DisplayPage, DisplayPopup, DisplayTouch, DisplayWAP:
		*d = display
	}
	return nil
}

type Gender string

type Locale struct {
	tag language.Tag
}

func NewLocale(tag language.Tag) *Locale {
	return &Locale{tag: tag}
}

func (l *Locale) Tag() language.Tag {
	if l == nil {
		return language.Und
	}

	return l.tag
}

func (l *Locale) String() string {
	return l.Tag().String()
}

func (l *Locale) MarshalJSON() ([]byte, error) {
	tag := l.Tag()
	if tag.IsRoot() {
		return []byte("null"), nil
	}

	return json.Marshal(tag)
}

// UnmarshalJSON implements json.Unmarshaler.
// When [language.ValueError] is encountered, the containing tag will be set
// to an empty value (language "und") and no error will be returned.
// This state can be checked with the `l.Tag().IsRoot()` method.
func (l *Locale) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "\"\"" {
		return nil
	}
	err := json.Unmarshal(data, &l.tag)
	if err == nil {
		return nil
	}

	// catch "well-formed but unknown" errors
	var target language.ValueError
	if errors.As(err, &target) {
		l.tag = language.Tag{}
		return nil
	}
	return err
}

type Locales []language.Tag

// ParseLocales parses a slice of strings into Locales.
// If an entry causes a parse error or is undefined,
// it is ignored and not set to Locales.
func ParseLocales(locales []string) Locales {
	out := make(Locales, 0, len(locales))
	for _, locale := range locales {
		tag, err := language.Parse(locale)
		if err == nil && !tag.IsRoot() {
			out = append(out, tag)
		}
	}
	return out
}

func (l Locales) String() string {
	tags := make([]string, len(l))
	for i, tag := range l {
		tags[i] = tag.String()
	}
	return strings.Join(tags, " ")
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
// It decodes an unquoted space separated string into Locales.
// Undefined language tags in the input are ignored and omitted from
// the resulting Locales.
func (l *Locales) UnmarshalText(text []byte) error {
	*l = ParseLocales(
		strings.Split(string(text), " "),
	)
	return nil
}

// UnmarshalJSON implements the [json.Unmarshaler] interface.
// It decodes a json array or a space separated string into Locales.
// Undefined language tags in the input are ignored and omitted from
// the resulting Locales.
func (l *Locales) UnmarshalJSON(data []byte) error {
	var dst any
	if err := json.Unmarshal(data, &dst); err != nil {
		return fmt.Errorf("oidc locales: %w", err)
	}

	// We catch the possibility of a space separated string here,
	// because UnmarshalText might have been implicitly called
	// by the json library before we added UnmarshalJSON.
	switch v := dst.(type) {
	case nil:
		*l = nil
	case string:
		*l = ParseLocales(strings.Split(v, " "))
	case []any:
		locales, err := gu.AssertInterfaces[string](v)
		if err != nil {
			return fmt.Errorf("oidc locales: %w", err)
		}
		*l = ParseLocales(locales)
	default:
		return fmt.Errorf("oidc locales: unsupported type: %T", v)
	}
	return nil
}

type MaxAge *uint

func NewMaxAge(i uint) MaxAge {
	return &i
}

type SpaceDelimitedArray []string

type Prompt SpaceDelimitedArray

type ResponseType string

type ResponseMode string

func (s SpaceDelimitedArray) String() string {
	return strings.Join(s, " ")
}

func (s *SpaceDelimitedArray) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), " ")
	return nil
}

func (s SpaceDelimitedArray) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s SpaceDelimitedArray) MarshalJSON() ([]byte, error) {
	return json.Marshal((s).String())
}

func (s *SpaceDelimitedArray) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = strings.Split(str, " ")
	return nil
}

func (s *SpaceDelimitedArray) Scan(src any) error {
	if src == nil {
		*s = nil
		return nil
	}
	switch v := src.(type) {
	case string:
		if len(v) == 0 {
			*s = SpaceDelimitedArray{}
			return nil
		}
		*s = strings.Split(v, " ")
	case []byte:
		if len(v) == 0 {
			*s = SpaceDelimitedArray{}
			return nil
		}
		*s = strings.Split(string(v), " ")
	default:
		return fmt.Errorf("cannot convert %T to SpaceDelimitedArray", src)
	}
	return nil
}

func (s SpaceDelimitedArray) Value() (driver.Value, error) {
	return strings.Join(s, " "), nil
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
		return fmt.Errorf("oidc: Encode expects struct, got %s", v.Kind())
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
	// Custom encoder
	if enc, ok := e.customEncoders[fv.Type()]; ok {
		return enc(fv)
	}
	// Pointer unwrap
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

type Time int64

func (ts Time) AsTime() time.Time {
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(int64(ts), 0)
}

func FromTime(tt time.Time) Time {
	if tt.IsZero() {
		return 0
	}
	return Time(tt.Unix())
}

func NowTime() Time {
	return FromTime(time.Now())
}

func (ts *Time) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("oidc.Time: %w", err)
	}
	switch x := v.(type) {
	case float64:
		*ts = Time(x)
	case string:
		// Compatibility with Auth0:
		// https://github.com/zitadel/oidc/issues/292
		tt, err := time.Parse(time.RFC3339, x)
		if err != nil {
			return fmt.Errorf("oidc.Time: %w", err)
		}
		*ts = FromTime(tt)
	case nil:
		*ts = 0
	default:
		return fmt.Errorf("oidc.Time: unable to parse type %T with value %v", x, x)
	}
	return nil
}

type RequestObject struct {
	Issuer   string   `json:"iss"`
	Audience Audience `json:"aud"`
	AuthRequest
}

func (r *RequestObject) GetIssuer() string {
	return r.Issuer
}

func (*RequestObject) SetSignatureAlgorithm(algorithm string) {}
