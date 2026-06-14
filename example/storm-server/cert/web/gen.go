//go:build ignore

// gen.go generates a self-signed TLS certificate for the storm-server HTTPS endpoint.
//
// Usage:
//
//	cd cert/web && go run gen.go
//
// Produces: server.crt, server.key
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatal(err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	fatal(err)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "KexCore OIDC Server",
			Organization: []string{"RoidMC Studios"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
			net.ParseIP("192.168.2.133"),
		},
		DNSNames: []string{
			"localhost",
			// Add your public domain here if using a real domain:
			// "kexoidc-test.example.com",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	fatal(err)

	cf, err := os.Create("server.crt")
	fatal(err)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	kf, err := os.Create("server.key")
	fatal(err)
	kb, err := x509.MarshalECPrivateKey(key)
	fatal(err)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	kf.Close()

	println("Done: server.crt, server.key")
	println("Valid for: localhost, 127.0.0.1, ::1")
	println("Expires: 10 years")
}

func fatal(err error) {
	if err != nil {
		panic(err)
	}
}
