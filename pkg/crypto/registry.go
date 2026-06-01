// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
)

// SignProvider is the interface for external JWS signing implementations.
// HSM/KMS vendors can implement this interface and register it to DefaultRegistry.
type SignProvider interface {
	// Algorithm returns the supported JWA signature algorithm, e.g. "SGD_SM3_SM2".
	Algorithm() string
	// Sign signs the payload with the key identified by keyID and returns compact JWS.
	Sign(ctx context.Context, keyID string, payload []byte) (string, error)
}

// VerifyProvider is the interface for external JWS signature verification.
type VerifyProvider interface {
	// Algorithm returns the supported JWA signature algorithm.
	Algorithm() string
	// Verify verifies the signature for the given signing input.
	// key is the public key material (type depends on algorithm, e.g. *ecdsa.PublicKey for SM2).
	Verify(ctx context.Context, signingInput, signature []byte, key interface{}) error
}

// JWEEncryptProvider is the interface for external JWE encryption implementations.
type JWEEncryptProvider interface {
	// KeyAlgorithm returns the JWE key wrapping algorithm, e.g. "SGD_SM2_3".
	KeyAlgorithm() string
	// ContentEncryption returns the JWE content encryption algorithm, e.g. "SGD_SM4_GCM".
	ContentEncryption() string
	// Encrypt encrypts plaintext and returns JWE compact serialization.
	// key is the encryption key material (type depends on algorithm).
	Encrypt(ctx context.Context, plaintext []byte, key interface{}) (string, error)
}

// JWEDecryptProvider is the interface for external JWE decryption implementations.
type JWEDecryptProvider interface {
	// KeyAlgorithm returns the JWE key wrapping algorithm.
	KeyAlgorithm() string
	// Decrypt decrypts JWE compact serialization and returns plaintext.
	// key is the decryption key material (type depends on algorithm).
	Decrypt(ctx context.Context, compact string, key interface{}) ([]byte, error)
}

// ProviderRegistry holds registered cryptographic providers.
// It is the central dispatch point for algorithm-specific implementations.
type ProviderRegistry struct {
	mu        sync.RWMutex
	signers   map[string]SignProvider
	verifiers map[string]VerifyProvider
	jweEnc    map[string]JWEEncryptProvider // keyed by keyAlgorithm
	jweDec    map[string]JWEDecryptProvider // keyed by keyAlgorithm
}

// NewProviderRegistry creates a new empty ProviderRegistry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		signers:   make(map[string]SignProvider),
		verifiers: make(map[string]VerifyProvider),
		jweEnc:    make(map[string]JWEEncryptProvider),
		jweDec:    make(map[string]JWEDecryptProvider),
	}
}

// DefaultRegistry is the global provider registry.
// Local gmsm implementations are registered in init().
var DefaultRegistry = NewProviderRegistry()

// RegisterSigner registers a SignProvider for the given algorithm.
func (r *ProviderRegistry) RegisterSigner(alg string, p SignProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signers[alg] = p
}

// GetSigner returns the registered SignProvider for the algorithm.
func (r *ProviderRegistry) GetSigner(alg string) (SignProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.signers[alg]
	return p, ok
}

// RegisterVerifier registers a VerifyProvider for the given algorithm.
func (r *ProviderRegistry) RegisterVerifier(alg string, p VerifyProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifiers[alg] = p
}

// GetVerifier returns the registered VerifyProvider for the algorithm.
func (r *ProviderRegistry) GetVerifier(alg string) (VerifyProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.verifiers[alg]
	return p, ok
}

// RegisterJWEEncryptor registers a JWEEncryptProvider for the given key algorithm.
func (r *ProviderRegistry) RegisterJWEEncryptor(alg string, p JWEEncryptProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jweEnc[alg] = p
}

// GetJWEEncryptor returns the registered JWEEncryptProvider for the key algorithm.
func (r *ProviderRegistry) GetJWEEncryptor(alg string) (JWEEncryptProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.jweEnc[alg]
	return p, ok
}

// RegisterJWEDecryptor registers a JWEDecryptProvider for the given key algorithm.
func (r *ProviderRegistry) RegisterJWEDecryptor(alg string, p JWEDecryptProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jweDec[alg] = p
}

// GetJWEDecryptor returns the registered JWEDecryptProvider for the key algorithm.
func (r *ProviderRegistry) GetJWEDecryptor(alg string) (JWEDecryptProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.jweDec[alg]
	return p, ok
}

// --- built-in gmsm providers ---

type sm2SignProvider struct{}

func (sm2SignProvider) Algorithm() string { return SGD_SM3_SM2 }

func (sm2SignProvider) Sign(ctx context.Context, keyID string, payload []byte) (string, error) {
	return "", fmt.Errorf("sm2SignProvider.Sign not yet implemented: use crypto.NewSigner directly")
}

type sm2VerifyProvider struct{}

func (sm2VerifyProvider) Algorithm() string { return SGD_SM3_SM2 }

func (sm2VerifyProvider) Verify(ctx context.Context, signingInput, signature []byte, key interface{}) error {
	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("sm2VerifyProvider: expected *ecdsa.PublicKey, got %T", key)
	}
	return VerifySM2JWSSignature(signingInput, signature, pubKey)
}

type sm9SignProvider struct{}

func (sm9SignProvider) Algorithm() string { return SGD_SM3_SM9 }

func (sm9SignProvider) Sign(ctx context.Context, keyID string, payload []byte) (string, error) {
	return "", fmt.Errorf("sm9SignProvider.Sign not yet implemented: use crypto.NewSigner directly")
}

type sm9VerifyProvider struct{}

func (sm9VerifyProvider) Algorithm() string { return SGD_SM3_SM9 }

func (sm9VerifyProvider) Verify(ctx context.Context, signingInput, signature []byte, key interface{}) error {
	return fmt.Errorf("sm9VerifyProvider.Verify not yet implemented")
}

type sm2JWEProvider struct{}

func (sm2JWEProvider) KeyAlgorithm() string      { return SGD_SM2_3 }
func (sm2JWEProvider) ContentEncryption() string { return SGD_SM4_GCM }

func (sm2JWEProvider) Encrypt(ctx context.Context, plaintext []byte, key interface{}) (string, error) {
	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("sm2JWEProvider: expected *ecdsa.PublicKey, got %T", key)
	}
	return SM2EncryptJWE(pubKey, plaintext)
}

func (sm2JWEProvider) Decrypt(ctx context.Context, compact string, key interface{}) ([]byte, error) {
	privKey, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("sm2JWEProvider: expected *sm2.PrivateKey, got %T", key)
	}
	return SM2DecryptJWE(privKey, compact)
}

type sm9JWEProvider struct{}

func (sm9JWEProvider) KeyAlgorithm() string      { return SGD_SM9_3 }
func (sm9JWEProvider) ContentEncryption() string { return SGD_SM4_GCM }

func (sm9JWEProvider) Encrypt(ctx context.Context, plaintext []byte, key interface{}) (string, error) {
	sm9Key, ok := key.(SM9EncryptKey)
	if !ok {
		return "", fmt.Errorf("sm9JWEProvider: expected SM9EncryptKey, got %T", key)
	}
	masterPubKey, uid, err := sm9Key.Resolve()
	if err != nil {
		return "", fmt.Errorf("sm9JWEProvider: failed to resolve SM9 key: %w", err)
	}
	return SM9EncryptJWE(masterPubKey, uid, SGD_SM4_GCM, plaintext)
}

func (sm9JWEProvider) Decrypt(ctx context.Context, compact string, key interface{}) ([]byte, error) {
	decKey, ok := key.(*SM9DecryptKey)
	if !ok {
		return nil, fmt.Errorf("sm9JWEProvider: expected *SM9DecryptKey, got %T", key)
	}
	return SM9DecryptJWE(decKey.PrivateKey, decKey.UID, compact)
}

// SM9EncryptKey is the crypto-layer interface for SM9 encryption keys.
// It abstracts away the gmsm-specific types so that callers (protocol layer)
// do not need to import gmsm directly.
type SM9EncryptKey interface {
	// Resolve returns the SM9 master public key and UID for encryption.
	Resolve() (masterPubKey *sm9.EncryptMasterPublicKey, uid []byte, err error)
}

// SM9DecryptKey wraps an SM9 encryption user private key and UID for JWE decryption.
type SM9DecryptKey struct {
	PrivateKey *sm9.EncryptPrivateKey
	UID        []byte
}

// SM9MasterPublicKey wraps an SM9 encryption master public key and UID
// to implement the SM9EncryptKey interface.
// It also implements protocol.SM9EncryptKey (MarshalBinary + UID).
type SM9MasterPublicKey struct {
	PublicKey *sm9.EncryptMasterPublicKey
	UID       []byte
}

func (k *SM9MasterPublicKey) Resolve() (*sm9.EncryptMasterPublicKey, []byte, error) {
	return k.PublicKey, k.UID, nil
}

func (k *SM9MasterPublicKey) GetUID() []byte {
	return k.UID
}

func (k *SM9MasterPublicKey) MarshalBinary() ([]byte, error) {
	if k.PublicKey == nil {
		return nil, fmt.Errorf("SM9MasterPublicKey: nil public key")
	}
	return k.PublicKey.MarshalASN1()
}

func init() {
	DefaultRegistry.RegisterSigner(SGD_SM3_SM2, sm2SignProvider{})
	DefaultRegistry.RegisterSigner(SGD_SM3_SM9, sm9SignProvider{})
	DefaultRegistry.RegisterVerifier(SGD_SM3_SM2, sm2VerifyProvider{})
	DefaultRegistry.RegisterVerifier(SGD_SM3_SM9, sm9VerifyProvider{})
	DefaultRegistry.RegisterJWEEncryptor(SGD_SM2_3, sm2JWEProvider{})
	DefaultRegistry.RegisterJWEEncryptor(SGD_SM9_3, sm9JWEProvider{})
	DefaultRegistry.RegisterJWEDecryptor(SGD_SM2_3, sm2JWEProvider{})
	DefaultRegistry.RegisterJWEDecryptor(SGD_SM9_3, sm9JWEProvider{})
}
