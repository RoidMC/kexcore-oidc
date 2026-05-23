// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"crypto/hmac"
	"encoding/hex"
	"hash"

	"github.com/emmansun/gmsm/sm3"
)

func SM3Hash(data []byte) []byte {
	h := sm3.New()
	h.Write(data)
	return h.Sum(nil)
}

func SM3HashHex(data []byte) string {
	return hex.EncodeToString(SM3Hash(data))
}

func SM3HashString(data string) []byte {
	return SM3Hash([]byte(data))
}

func SM3HashStringHex(data string) string {
	return SM3HashHex([]byte(data))
}

func SM3Sum(data []byte) [sm3.Size]byte {
	return sm3.Sum(data)
}

type SM3 struct {
	h hash.Hash
}

func NewSM3() *SM3 {
	return &SM3{h: sm3.New()}
}

func (s *SM3) Write(data []byte) (int, error) {
	return s.h.Write(data)
}

func (s *SM3) Sum(b []byte) []byte {
	return s.h.Sum(b)
}

func (s *SM3) Reset() {
	s.h.Reset()
}

func (s *SM3) Size() int {
	return s.h.Size()
}

func (s *SM3) BlockSize() int {
	return s.h.BlockSize()
}

// SM3HMAC returns the SM3-based HMAC of data using the given key (SGD_SM3_HMAC).
func SM3HMAC(key, data []byte) []byte {
	h := hmac.New(sm3.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// SM3HMACHex returns the SM3-based HMAC of data as a hex-encoded string.
func SM3HMACHex(key, data []byte) string {
	return hex.EncodeToString(SM3HMAC(key, data))
}

// SM3HMACVerify checks whether the given HMAC matches the SM3-HMAC of data.
func SM3HMACVerify(key, data, mac []byte) bool {
	expected := SM3HMAC(key, data)
	return hmac.Equal(mac, expected)
}
