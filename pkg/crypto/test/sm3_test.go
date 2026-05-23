// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/roidmc/kexcore-oidc/v1/pkg/crypto"
)

func TestSM3Hash(t *testing.T) {
	data := []byte("test message")
	hash := crypto.SM3Hash(data)

	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}
}

func TestSM3HashHex(t *testing.T) {
	data := []byte("test message")
	hashHex := crypto.SM3HashHex(data)

	if len(hashHex) != 64 {
		t.Errorf("expected hex hash length 64, got %d", len(hashHex))
	}

	_, err := hex.DecodeString(hashHex)
	if err != nil {
		t.Errorf("hash hex is not valid hex: %v", err)
	}
}

func TestSM3HashString(t *testing.T) {
	data := "test message"
	hash := crypto.SM3HashString(data)

	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}
}

func TestSM3HashStringHex(t *testing.T) {
	data := "test message"
	hashHex := crypto.SM3HashStringHex(data)

	if len(hashHex) != 64 {
		t.Errorf("expected hex hash length 64, got %d", len(hashHex))
	}
}

func TestSM3Sum(t *testing.T) {
	data := []byte("test message")
	hash := crypto.SM3Sum(data)

	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}
}

func TestSM3Consistency(t *testing.T) {
	data := []byte("test message")

	hash1 := crypto.SM3Hash(data)
	hash2 := crypto.SM3Hash(data)

	if string(hash1) != string(hash2) {
		t.Error("same input should produce same hash")
	}

	hash3 := crypto.SM3Sum(data)
	if string(hash1) != string(hash3[:]) {
		t.Error("SM3Hash and SM3Sum should produce same result")
	}
}

func TestSM3EmptyInput(t *testing.T) {
	empty := []byte{}

	hash := crypto.SM3Hash(empty)
	if len(hash) != 32 {
		t.Errorf("expected hash length 32 for empty input, got %d", len(hash))
	}
}

func TestSM3KnownVectors(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
	}

	for _, tt := range tests {
		hashHex := crypto.SM3HashStringHex(tt.input)
		if hashHex != tt.expected {
			t.Errorf("SM3(%q) = %s, want %s", tt.input, hashHex, tt.expected)
		}
	}
}

func TestSM3Struct(t *testing.T) {
	h := crypto.NewSM3()

	h.Write([]byte("test"))
	h.Write([]byte(" "))
	h.Write([]byte("message"))

	hash := h.Sum(nil)
	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}

	h.Reset()
	h.Write([]byte("test message"))

	hash2 := h.Sum(nil)
	if string(hash) != string(hash2) {
		t.Error("incremental hash should match single write")
	}
}

func TestSM3Size(t *testing.T) {
	h := crypto.NewSM3()

	if h.Size() != 32 {
		t.Errorf("expected size 32, got %d", h.Size())
	}
}

func TestSM3BlockSize(t *testing.T) {
	h := crypto.NewSM3()

	if h.BlockSize() != 64 {
		t.Errorf("expected block size 64, got %d", h.BlockSize())
	}
}

func TestSM3WriteReturn(t *testing.T) {
	h := crypto.NewSM3()
	data := []byte("test message")

	n, err := h.Write(data)
	if err != nil {
		t.Errorf("Write returned error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, expected %d", n, len(data))
	}
}

func TestSM3SumWithPrefix(t *testing.T) {
	h := crypto.NewSM3()
	h.Write([]byte("test"))

	prefix := []byte("prefix:")
	result := h.Sum(prefix)

	if len(result) != len(prefix)+32 {
		t.Errorf("expected result length %d, got %d", len(prefix)+32, len(result))
	}

	if string(result[:len(prefix)]) != string(prefix) {
		t.Error("prefix not preserved in Sum result")
	}
}

func TestSM3LongInput(t *testing.T) {
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	hash := crypto.SM3Hash(data)
	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}
}
