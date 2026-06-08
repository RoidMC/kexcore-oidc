// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/roidmc/kexcore-oidc/pkg/crypto/gm"
)

func TestSM3Hash(t *testing.T) {
	data := []byte("test message")
	hash := gm.SM3Hash(data)

	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}
}

func TestSM3HashHex(t *testing.T) {
	data := []byte("test message")
	hashHex := gm.SM3HashHex(data)

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
	hash := gm.SM3HashString(data)

	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}
}

func TestSM3HashStringHex(t *testing.T) {
	data := "test message"
	hashHex := gm.SM3HashStringHex(data)

	if len(hashHex) != 64 {
		t.Errorf("expected hex hash length 64, got %d", len(hashHex))
	}
}

func TestSM3Sum(t *testing.T) {
	data := []byte("test message")
	hash := gm.SM3Sum(data)

	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}
}

func TestSM3Consistency(t *testing.T) {
	data := []byte("test message")

	hash1 := gm.SM3Hash(data)
	hash2 := gm.SM3Hash(data)

	if string(hash1) != string(hash2) {
		t.Error("same input should produce same hash")
	}

	hash3 := gm.SM3Sum(data)
	if string(hash1) != string(hash3[:]) {
		t.Error("SM3Hash and SM3Sum should produce same result")
	}
}

func TestSM3EmptyInput(t *testing.T) {
	empty := []byte{}

	hash := gm.SM3Hash(empty)
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
		hashHex := gm.SM3HashStringHex(tt.input)
		if hashHex != tt.expected {
			t.Errorf("SM3(%q) = %s, want %s", tt.input, hashHex, tt.expected)
		}
	}
}

func TestSM3Struct(t *testing.T) {
	h := gm.NewSM3()

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
	h := gm.NewSM3()

	if h.Size() != 32 {
		t.Errorf("expected size 32, got %d", h.Size())
	}
}

func TestSM3BlockSize(t *testing.T) {
	h := gm.NewSM3()

	if h.BlockSize() != 64 {
		t.Errorf("expected block size 64, got %d", h.BlockSize())
	}
}

func TestSM3WriteReturn(t *testing.T) {
	h := gm.NewSM3()
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
	h := gm.NewSM3()
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

	hash := gm.SM3Hash(data)
	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}
}

// --- SM3-HMAC tests ---

func TestSM3HMAC(t *testing.T) {
	key := []byte("test-hmac-key")
	data := []byte("test message for SM3-HMAC")

	mac := gm.SM3HMAC(key, data)
	if len(mac) != 32 {
		t.Errorf("expected HMAC length 32, got %d", len(mac))
	}
}

func TestSM3HMACHex(t *testing.T) {
	key := []byte("test-hmac-key")
	data := []byte("test message")

	macHex := gm.SM3HMACHex(key, data)
	if len(macHex) != 64 {
		t.Errorf("expected hex HMAC length 64, got %d", len(macHex))
	}

	_, err := hex.DecodeString(macHex)
	if err != nil {
		t.Errorf("HMAC hex is not valid hex: %v", err)
	}
}

func TestSM3HMACConsistency(t *testing.T) {
	key := []byte("test-hmac-key")
	data := []byte("test message")

	mac1 := gm.SM3HMAC(key, data)
	mac2 := gm.SM3HMAC(key, data)

	if string(mac1) != string(mac2) {
		t.Error("same key and data should produce same HMAC")
	}
}

func TestSM3HMACVerify(t *testing.T) {
	key := []byte("test-hmac-key")
	data := []byte("test message")

	mac := gm.SM3HMAC(key, data)

	if !gm.SM3HMACVerify(key, data, mac) {
		t.Error("HMAC verification should succeed with correct key and data")
	}

	if gm.SM3HMACVerify([]byte("wrong-key"), data, mac) {
		t.Error("HMAC verification should fail with wrong key")
	}

	if gm.SM3HMACVerify(key, []byte("wrong-data"), mac) {
		t.Error("HMAC verification should fail with wrong data")
	}

	tamperedMAC := make([]byte, len(mac))
	copy(tamperedMAC, mac)
	tamperedMAC[0] ^= 0xff
	if gm.SM3HMACVerify(key, data, tamperedMAC) {
		t.Error("HMAC verification should fail with tampered MAC")
	}
}

func TestSM3HMACDifferentKeys(t *testing.T) {
	data := []byte("same data")
	key1 := []byte("key-1")
	key2 := []byte("key-2")

	mac1 := gm.SM3HMAC(key1, data)
	mac2 := gm.SM3HMAC(key2, data)

	if string(mac1) == string(mac2) {
		t.Error("different keys should produce different HMACs")
	}
}

func TestSM3HMACEmptyInput(t *testing.T) {
	key := []byte("test-hmac-key")

	mac := gm.SM3HMAC(key, []byte{})
	if len(mac) != 32 {
		t.Errorf("expected HMAC length 32 for empty input, got %d", len(mac))
	}
}
