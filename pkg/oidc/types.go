// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package oidc

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type Audience = protocol.Audience

type AuthenticationMethodsReferences = protocol.AuthenticationMethodsReferences

type Display = protocol.Display

type GrantType = protocol.GrantType

const (
	GrantTypeCode              = protocol.GrantTypeCode
	GrantTypeRefreshToken      = protocol.GrantTypeRefreshToken
	GrantTypeClientCredentials = protocol.GrantTypeClientCredentials
	GrantTypeBearer            = protocol.GrantTypeBearer
	GrantTypeTokenExchange     = protocol.GrantTypeTokenExchange
	GrantTypeImplicit          = protocol.GrantTypeImplicit
	GrantTypeDeviceCode        = protocol.GrantTypeDeviceCode
)

type TokenType = protocol.TokenType

const (
	AccessTokenType  = protocol.AccessTokenType
	RefreshTokenType = protocol.RefreshTokenType
	IDTokenType      = protocol.IDTokenType
	JWTTokenType     = protocol.JWTTokenType
)

type Gender = protocol.Gender

type Locale = protocol.Locale

var NewLocale = protocol.NewLocale

type Locales = protocol.Locales

var ParseLocales = protocol.ParseLocales

type MaxAge = protocol.MaxAge

var NewMaxAge = protocol.NewMaxAge

type SpaceDelimitedArray = protocol.SpaceDelimitedArray

type Prompt = protocol.SpaceDelimitedArray

type ResponseType = protocol.ResponseType

type ResponseMode = protocol.ResponseMode

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

type Time = protocol.Time

func FromTime(tt time.Time) Time {
	return protocol.FromTime(tt)
}

func NowTime() Time {
	return protocol.NowTime()
}

type RequestObject struct {
	Issuer   string   `json:"iss"`
	Audience Audience `json:"aud"`
	protocol.AuthRequest
}

func (r *RequestObject) GetIssuer() string {
	return r.Issuer
}

func (*RequestObject) SetSignatureAlgorithm(algorithm string) {}
