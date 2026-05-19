package crypto

import (
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
