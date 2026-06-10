// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package util

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func TestParseJWECompact_Valid(t *testing.T) {
	header := JWEHeader{Algorithm: "SGD_SM2_3", Encryption: "SGD_SM4_GCM"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	compact := headerB64 + ".key.iv.ct.tag"

	parts, hdr, err := ParseJWECompact(compact)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d", len(parts))
	}
	if hdr.Algorithm != "SGD_SM2_3" {
		t.Errorf("expected alg=SGD_SM2_3, got %s", hdr.Algorithm)
	}
	if hdr.Encryption != "SGD_SM4_GCM" {
		t.Errorf("expected enc=SGD_SM4_GCM, got %s", hdr.Encryption)
	}
}

func TestParseJWECompact_TooFewParts(t *testing.T) {
	_, _, err := ParseJWECompact("a.b.c")
	if !errors.Is(err, ErrInvalidJWEParts) {
		t.Errorf("expected ErrInvalidJWEParts, got %v", err)
	}
}

func TestParseJWECompact_TooManyParts(t *testing.T) {
	_, _, err := ParseJWECompact("a.b.c.d.e.f")
	if !errors.Is(err, ErrInvalidJWEParts) {
		t.Errorf("expected ErrInvalidJWEParts, got %v", err)
	}
}

func TestParseJWECompact_EmptyString(t *testing.T) {
	_, _, err := ParseJWECompact("")
	if !errors.Is(err, ErrInvalidJWEParts) {
		t.Errorf("expected ErrInvalidJWEParts, got %v", err)
	}
}

func TestParseJWECompact_EmptyPart(t *testing.T) {
	_, _, err := ParseJWECompact("a.b..d.e")
	if !errors.Is(err, ErrInvalidJWECompact) {
		t.Errorf("expected ErrInvalidJWECompact, got %v", err)
	}
}

func TestParseJWECompact_InvalidBase64(t *testing.T) {
	_, _, err := ParseJWECompact("!!!.b.c.d.e")
	if !errors.Is(err, ErrInvalidJWECompact) {
		t.Errorf("expected ErrInvalidJWECompact, got %v", err)
	}
}

func TestParseJWECompact_InvalidJSON(t *testing.T) {
	badHeader := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	_, _, err := ParseJWECompact(badHeader + ".b.c.d.e")
	if !errors.Is(err, ErrInvalidJWECompact) {
		t.Errorf("expected ErrInvalidJWECompact, got %v", err)
	}
}

func TestParseJWECompact_OptionalFields(t *testing.T) {
	header := JWEHeader{
		Algorithm:   "RSA-OAEP",
		Encryption:  "A256GCM",
		Type:        "JWT",
		ContentType: "application/json",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	_, hdr, err := ParseJWECompact(headerB64 + ".k.i.c.t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hdr.Type != "JWT" {
		t.Errorf("expected typ=JWT, got %s", hdr.Type)
	}
	if hdr.ContentType != "application/json" {
		t.Errorf("expected cty=application/json, got %s", hdr.ContentType)
	}
}
