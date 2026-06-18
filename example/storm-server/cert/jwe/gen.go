//go:build ignore

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
)

func main() {
	dir := filepath.Join(".", "jwe")
	os.MkdirAll(dir, 0o755)

	// 生成RSA密钥用于ID token加密 (RSA-OAEP)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	jwk := map[string]string{
		"kty": "RSA",
		"use": "enc",
		"kid": "jwe-enc-key-1",
		"alg": "RSA-OAEP",
		"n":   b64url(key.N.Bytes()),
		"e":   b64url(big.NewInt(int64(key.E)).Bytes()),
		"d":   b64url(key.D.Bytes()),
	}
	jwkSet := map[string]any{"keys": []any{jwk}}

	jf, _ := os.Create(filepath.Join(dir, "enc_jwk.json"))
	enc := json.NewEncoder(jf)
	enc.SetIndent("", "  ")
	enc.Encode(jwkSet)
	jf.Close()

	println("Done: jwe/enc_jwk.json")
	println("Algorithm: RSA-OAEP (2048-bit)")
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
