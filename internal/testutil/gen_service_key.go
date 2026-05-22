// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

//go:build ignore

// gen_service_key generates a new 2048-bit RSA key for the service.
// Run with: go run gen_service_key.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Write PEM
	privDER := x509.MarshalPKCS1PrivateKey(key)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})
	os.WriteFile("service-key1.pem", privPEM, 0600)

	// Print public key for Go code
	fmt.Printf("N: %s\n", hex.EncodeToString(key.N.Bytes()))
	fmt.Printf("E: %d\n", key.E)
	fmt.Printf("\n&rsa.PublicKey{\n\tN: func() *big.Int {\n\t\tn, _ := new(big.Int).SetString(\"%x\", 16)\n\t\treturn n\n\t}(),\n\tE: %d,\n}\n", key.N, key.E)
}
