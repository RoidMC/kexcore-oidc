//go:build ignore

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := filepath.Join(".", "cert")
	os.MkdirAll(dir, 0o755)

	// 1. 生成CA证书
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "KexCore FAPI Test CA",
			Organization: []string{"RoidMC Studios"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10年
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)

	// 保存CA证书
	caCertFile, _ := os.Create(filepath.Join(dir, "ca.crt"))
	pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caCertFile.Close()

	// 保存CA私钥
	caKeyFile, _ := os.Create(filepath.Join(dir, "ca.key"))
	caKeyBytes, _ := x509.MarshalPKCS8PrivateKey(caKey)
	pem.Encode(caKeyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: caKeyBytes})
	caKeyFile.Close()

	// 2. 用CA签发客户端证书
	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	clientTmpl := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject: pkix.Name{
			CommonName:   "KexCore FAPI Test Client",
			Organization: []string{"RoidMC Studios"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1年
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, _ := x509.CreateCertificate(rand.Reader, clientTmpl, caTmpl, &clientKey.PublicKey, caKey)

	// 保存客户端证书
	clientCertFile, _ := os.Create(filepath.Join(dir, "client.crt"))
	pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	clientCertFile.Close()

	// 保存客户端私钥
	clientKeyFile, _ := os.Create(filepath.Join(dir, "client.key"))
	clientKeyBytes, _ := x509.MarshalPKCS8PrivateKey(clientKey)
	pem.Encode(clientKeyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyBytes})
	clientKeyFile.Close()

	// 3. 生成JWK用于ID token加密
	jwk := map[string]string{
		"kty": "RSA",
		"use": "enc",
		"kid": "mtls-demo-enc-key-1",
		"alg": "RSA-OAEP",
		"n":   b64url(clientKey.N.Bytes()),
		"e":   b64url(big.NewInt(int64(clientKey.E)).Bytes()),
	}
	jwkSet := map[string]any{"keys": []any{jwk}}
	jf, _ := os.Create(filepath.Join(dir, "client_enc_jwk.json"))
	enc := json.NewEncoder(jf)
	enc.SetIndent("", "  ")
	enc.Encode(jwkSet)
	jf.Close()

	println("Done: ca.crt, ca.key, client.crt, client.key, client_enc_jwk.json")
	println("CA: KexCore FAPI Test CA (10 years)")
	println("Client: KexCore FAPI Test Client (1 year)")
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
