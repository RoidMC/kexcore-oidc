package crypto_test

import (
	"bytes"
	"testing"

	"github.com/roidmc/kexcore-oidc/v1/pkg/crypto"
)

func TestSM2GenerateKey(t *testing.T) {
	privateKey, err := crypto.SM2GenerateKey()
	if err != nil {
		t.Fatalf("SM2GenerateKey failed: %v", err)
	}
	if privateKey == nil {
		t.Fatal("private key is nil")
	}
	pubBytes, err := crypto.SM2PublicKeyToBytes(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("SM2PublicKeyToBytes failed: %v", err)
	}
	if len(pubBytes) == 0 {
		t.Fatal("public key bytes is empty")
	}
}

func TestSM2SignVerify(t *testing.T) {
	privateKey, _ := crypto.SM2GenerateKey()
	data := []byte("test message for SM2 signature")

	signature, err := crypto.SM2Sign(privateKey, data)
	if err != nil {
		t.Fatalf("SM2Sign failed: %v", err)
	}

	valid := crypto.SM2Verify(&privateKey.PublicKey, data, signature)
	if !valid {
		t.Error("signature verification failed")
	}

	wrongData := []byte("wrong message")
	valid = crypto.SM2Verify(&privateKey.PublicKey, wrongData, signature)
	if valid {
		t.Error("signature should not be valid for wrong data")
	}
}

func TestSM2SignVerifyWithUID(t *testing.T) {
	privateKey, _ := crypto.SM2GenerateKey()
	uid := []byte("testuser@example.com")
	data := []byte("test message with UID")

	signature, err := crypto.SM2SignWithUID(privateKey, uid, data)
	if err != nil {
		t.Fatalf("SM2SignWithUID failed: %v", err)
	}

	valid := crypto.SM2VerifyWithUID(&privateKey.PublicKey, uid, data, signature)
	if !valid {
		t.Error("signature verification with UID failed")
	}

	wrongUID := []byte("wrong@example.com")
	valid = crypto.SM2VerifyWithUID(&privateKey.PublicKey, wrongUID, data, signature)
	if valid {
		t.Error("signature should not be valid for wrong UID")
	}
}

func TestSM2EncryptDecrypt(t *testing.T) {
	privateKey, _ := crypto.SM2GenerateKey()
	plaintext := []byte("test message for SM2 encryption")

	ciphertext, err := crypto.SM2Encrypt(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2Encrypt failed: %v", err)
	}

	decrypted, err := crypto.SM2Decrypt(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("SM2Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match plaintext\ngot: %s\nwant: %s", decrypted, plaintext)
	}
}

func TestSM2EncryptDecryptASN1(t *testing.T) {
	privateKey, _ := crypto.SM2GenerateKey()
	plaintext := []byte("test message for SM2 ASN1 encryption")

	ciphertext, err := crypto.SM2EncryptASN1(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2EncryptASN1 failed: %v", err)
	}

	decrypted, err := crypto.SM2Decrypt(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("SM2Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match plaintext")
	}
}

func TestSM2KeyConversion(t *testing.T) {
	privateKey, _ := crypto.SM2GenerateKey()

	hexPrivKey, err := crypto.SM2PrivateKeyToHex(privateKey)
	if err != nil {
		t.Fatalf("SM2PrivateKeyToHex failed: %v", err)
	}
	if hexPrivKey == "" {
		t.Error("private key hex is empty")
	}

	hexPubKey, err := crypto.SM2PublicKeyToHex(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("SM2PublicKeyToHex failed: %v", err)
	}
	if hexPubKey == "" {
		t.Error("public key hex is empty")
	}

	privKeyBytes, err := crypto.SM2PrivateKeyToBytes(privateKey)
	if err != nil {
		t.Fatalf("SM2PrivateKeyToBytes failed: %v", err)
	}
	reconstructedKey, err := crypto.SM2NewPrivateKey(privKeyBytes)
	if err != nil {
		t.Fatalf("SM2NewPrivateKey failed: %v", err)
	}

	if !privateKey.Equal(reconstructedKey) {
		t.Error("reconstructed private key doesn't match")
	}
}

func TestSM2PublicKeyRoundTrip(t *testing.T) {
	privateKey, _ := crypto.SM2GenerateKey()

	pubBytes, err := crypto.SM2PublicKeyToBytes(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("SM2PublicKeyToBytes failed: %v", err)
	}

	reconstructedPub, err := crypto.SM2NewPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("SM2NewPublicKey failed: %v", err)
	}

	if !privateKey.PublicKey.Equal(reconstructedPub) {
		t.Error("reconstructed public key doesn't match")
	}
}

func TestSM2CalculateZA(t *testing.T) {
	privateKey, _ := crypto.SM2GenerateKey()
	uid := []byte("testuser@example.com")

	za, err := crypto.SM2CalculateZA(&privateKey.PublicKey, uid)
	if err != nil {
		t.Fatalf("SM2CalculateZA failed: %v", err)
	}

	if len(za) != 32 {
		t.Errorf("expected ZA length 32, got %d", len(za))
	}
}

func TestSM2EmptyPlaintext(t *testing.T) {
	privateKey, _ := crypto.SM2GenerateKey()
	plaintext := []byte{}

	ciphertext, err := crypto.SM2Encrypt(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2Encrypt failed: %v", err)
	}

	_, err = crypto.SM2Decrypt(privateKey, ciphertext)
	if err == nil {
		t.Error("expected error for empty plaintext decryption")
	}
}

func TestSM2TamperedCiphertext(t *testing.T) {
	privateKey, _ := crypto.SM2GenerateKey()
	plaintext := []byte("test message")

	ciphertext, err := crypto.SM2Encrypt(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2Encrypt failed: %v", err)
	}

	ciphertext[0] ^= 0xFF

	_, err = crypto.SM2Decrypt(privateKey, ciphertext)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestSM2TamperedSignature(t *testing.T) {
	privateKey, _ := crypto.SM2GenerateKey()
	data := []byte("test message")

	signature, _ := crypto.SM2Sign(privateKey, data)

	signature[0] ^= 0xFF

	valid := crypto.SM2Verify(&privateKey.PublicKey, data, signature)
	if valid {
		t.Error("tampered signature should not be valid")
	}
}
