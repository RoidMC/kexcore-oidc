//go:build ignore

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := filepath.Join(".", "mtls")
	os.MkdirAll(dir, 0o755)

	// 1. 生成CA证书（与主CA共用）
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "KexCore mTLS Test CA",
			Organization: []string{"RoidMC Studios"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)

	// 保存CA证书和私钥
	writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", caCertDER)
	caKeyBytes, _ := x509.MarshalPKCS8PrivateKey(caKey)
	writePEM(filepath.Join(dir, "ca.key"), "PRIVATE KEY", caKeyBytes)

	// 2. 为每个FAPI客户端生成独立证书
	clients := []struct {
		name string // 用作CommonName，必须与client_id一致
		file string // 文件名前缀
	}{
		{"FAPI Client 1", "client1"},
		{"FAPI Client 2", "client2"},
	}

	for _, c := range clients {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				CommonName:   c.name,
				Organization: []string{"RoidMC Studios"},
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &key.PublicKey, caKey)

		writePEM(filepath.Join(dir, c.file+".crt"), "CERTIFICATE", certDER)
		keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
		writePEM(filepath.Join(dir, c.file+".key"), "PRIVATE KEY", keyBytes)

		fmt.Printf("Generated: %s.crt (CN=%s)\n", c.file, c.name)
	}

	fmt.Println("Done: mtls/ca.crt, mtls/ca.key, mtls/client1.crt, mtls/client1.key, mtls/client2.crt, mtls/client2.key")
}

func writePEM(path, blockType string, data []byte) {
	f, _ := os.Create(path)
	pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
	f.Close()
}
