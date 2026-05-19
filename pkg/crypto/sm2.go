// Copyright (c) 2026 KexCore

package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/emmansun/gmsm/sm2"
)

var (
	ErrInvalidSM2PrivateKey = errors.New("kexcore/crypto: sm2 invalid private key")
	ErrInvalidSM2PublicKey  = errors.New("kexcore/crypto: sm2 invalid public key")
)

func SM2GenerateKey() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

func SM2Sign(privateKey *sm2.PrivateKey, data []byte) ([]byte, error) {
	return sm2.SignASN1(rand.Reader, privateKey, data, nil)
}

func SM2SignWithUID(privateKey *sm2.PrivateKey, uid, data []byte) ([]byte, error) {
	return privateKey.SignWithSM2(rand.Reader, uid, data)
}

func SM2Verify(publicKey *ecdsa.PublicKey, data, signature []byte) bool {
	return sm2.VerifyASN1(publicKey, data, signature)
}

func SM2VerifyWithUID(publicKey *ecdsa.PublicKey, uid, data, signature []byte) bool {
	return sm2.VerifyASN1WithSM2(publicKey, uid, data, signature)
}

func SM2Encrypt(publicKey *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	return sm2.Encrypt(rand.Reader, publicKey, plaintext, nil)
}

func SM2EncryptASN1(publicKey *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	return sm2.EncryptASN1(rand.Reader, publicKey, plaintext)
}

func SM2Decrypt(privateKey *sm2.PrivateKey, ciphertext []byte) ([]byte, error) {
	return sm2.Decrypt(privateKey, ciphertext)
}

func SM2NewPublicKey(key []byte) (*ecdsa.PublicKey, error) {
	return sm2.NewPublicKey(key)
}

func SM2NewPrivateKey(key []byte) (*sm2.PrivateKey, error) {
	return sm2.NewPrivateKey(key)
}

func SM2PublicKeyToBytes(publicKey *ecdsa.PublicKey) ([]byte, error) {
	ecdhKey, err := sm2.PublicKeyToECDH(publicKey)
	if err != nil {
		return nil, err
	}
	return ecdhKey.Bytes(), nil
}

func SM2PublicKeyToHex(publicKey *ecdsa.PublicKey) (string, error) {
	b, err := SM2PublicKeyToBytes(publicKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func SM2PrivateKeyToBytes(privateKey *sm2.PrivateKey) ([]byte, error) {
	ecdhKey, err := privateKey.ECDH()
	if err != nil {
		return nil, err
	}
	return ecdhKey.Bytes(), nil
}

func SM2PrivateKeyToHex(privateKey *sm2.PrivateKey) (string, error) {
	b, err := SM2PrivateKeyToBytes(privateKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func SM2CalculateZA(publicKey *ecdsa.PublicKey, uid []byte) ([]byte, error) {
	return sm2.CalculateZA(publicKey, uid)
}

func SM2KeyExchange(priv *sm2.PrivateKey, peerPub *ecdsa.PublicKey, uid, peerUID []byte, keyLen int, isResponder bool) (*sm2.KeyExchange, error) {
	return sm2.NewKeyExchange(priv, peerPub, uid, peerUID, keyLen, isResponder)
}
