// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"sync"

	gmsm "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
	gm "github.com/roidmc/kexcore-oidc/v3/pkg/crypto/gm"
	"github.com/roidmc/kexcore-oidc/v3/pkg/crypto/provider/std"
)

// SignProvider is the interface for JWS signing implementations.
// Both built-in software signers and HSM/KMS vendors implement this interface
// and register it to DefaultRegistry. Registering the same algorithm twice
// panics; a vendor that intentionally replaces a built-in implementation must
// call ProviderRegistry.OverrideSigner instead.
type SignProvider interface {
	// Algorithm returns the supported JWA signature algorithm, e.g. "SGD_SM3_SM2".
	Algorithm() string
	// Sign signs the payload and returns compact JWS.
	// key is the signing key material; type depends on algorithm (e.g. *sm2.PrivateKey for SM2).
	// tokenType is the JWT typ header value (e.g. "JWT", "logout+jwt"); HSM providers may ignore it.
	// HSM/KMS providers can ignore key if they locate key material by keyID internally.
	Sign(ctx context.Context, keyID, tokenType string, key interface{}, payload []byte) (string, error)
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

// ContentEncryptProvider is the interface for external JWE content encryption implementations.
// Used for "dir" mode where key wrapping is "dir" and content encryption is the actual algorithm.
// HSM/KMS vendors can implement this to provide hardware-accelerated content encryption.
type ContentEncryptProvider interface {
	// Algorithm returns the JWE content encryption algorithm, e.g. "SGD_SM4_GCM", "A256GCM".
	Algorithm() string
	// Encrypt encrypts plaintext with the given key, IV, and AAD.
	// Returns ciphertext + GCM tag concatenated.
	Encrypt(ctx context.Context, key, iv, plaintext, aad []byte) ([]byte, error)
}

// ContentDecryptProvider is the interface for external JWE content decryption implementations.
type ContentDecryptProvider interface {
	// Algorithm returns the JWE content encryption algorithm.
	Algorithm() string
	// Decrypt decrypts ciphertext with the given key, IV, and AAD.
	// Input sealed is ciphertext + GCM tag concatenated.
	Decrypt(ctx context.Context, key, iv, sealed, aad []byte) ([]byte, error)
}

// ProviderRegistry holds registered cryptographic providers.
// It is the central dispatch point for algorithm-specific implementations.
type ProviderRegistry struct {
	mu         sync.RWMutex
	signers    map[string]SignProvider
	verifiers  map[string]VerifyProvider
	jweEnc     map[string]JWEEncryptProvider     // keyed by keyAlgorithm
	jweDec     map[string]JWEDecryptProvider     // keyed by keyAlgorithm
	contentEnc map[string]ContentEncryptProvider // keyed by content encryption algorithm
	contentDec map[string]ContentDecryptProvider // keyed by content encryption algorithm
}

// NewProviderRegistry creates a new empty ProviderRegistry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		signers:    make(map[string]SignProvider),
		verifiers:  make(map[string]VerifyProvider),
		jweEnc:     make(map[string]JWEEncryptProvider),
		jweDec:     make(map[string]JWEDecryptProvider),
		contentEnc: make(map[string]ContentEncryptProvider),
		contentDec: make(map[string]ContentDecryptProvider),
	}
}

// DefaultRegistry is the global provider registry.
// Built-in software implementations are registered in init().
var DefaultRegistry = NewProviderRegistry()

// putProvider is the single write path for every provider map. It enforces
// the two invariants that used to fail silently:
//   - the registry key must match the algorithm the provider advertises;
//   - duplicate registration is a programming error unless the caller uses
//     the matching Override* method.
func putProvider[T any](r *ProviderRegistry, m map[string]T, kind, overrideName, alg, declared string, p T, override bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if declared != alg {
		panic(fmt.Sprintf("crypto: %s registered for %q advertises algorithm %q", kind, alg, declared))
	}
	if _, exists := m[alg]; exists {
		if !override {
			panic(fmt.Sprintf("crypto: duplicate %s for %q; use %s to replace an existing implementation", kind, alg, overrideName))
		}
		slog.Info("crypto: provider overridden", "kind", kind, "alg", alg)
	}
	m[alg] = p
}

// RegisterSigner registers a SignProvider for the given algorithm.
// It panics if alg is already registered or if p advertises a different
// algorithm. Use OverrideSigner to replace an existing implementation.
func (r *ProviderRegistry) RegisterSigner(alg string, p SignProvider) {
	putProvider(r, r.signers, "sign provider", "OverrideSigner", alg, p.Algorithm(), p, false)
}

// OverrideSigner replaces (or adds) a SignProvider for the given algorithm.
// This is the only supported way for HSM/KMS vendors to replace a built-in
// implementation.
func (r *ProviderRegistry) OverrideSigner(alg string, p SignProvider) {
	putProvider(r, r.signers, "sign provider", "OverrideSigner", alg, p.Algorithm(), p, true)
}

// GetSigner returns the registered SignProvider for the algorithm.
func (r *ProviderRegistry) GetSigner(alg string) (SignProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.signers[alg]
	return p, ok
}

// RegisterVerifier registers a VerifyProvider for the given algorithm.
// It panics if alg is already registered or if p advertises a different
// algorithm. Use OverrideVerifier to replace an existing implementation.
func (r *ProviderRegistry) RegisterVerifier(alg string, p VerifyProvider) {
	putProvider(r, r.verifiers, "verify provider", "OverrideVerifier", alg, p.Algorithm(), p, false)
}

// OverrideVerifier replaces (or adds) a VerifyProvider for the given algorithm.
func (r *ProviderRegistry) OverrideVerifier(alg string, p VerifyProvider) {
	putProvider(r, r.verifiers, "verify provider", "OverrideVerifier", alg, p.Algorithm(), p, true)
}

// GetVerifier returns the registered VerifyProvider for the algorithm.
func (r *ProviderRegistry) GetVerifier(alg string) (VerifyProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.verifiers[alg]
	return p, ok
}

// RegisterJWEEncryptor registers a JWEEncryptProvider for the given key algorithm.
// It panics on duplicate registration or key/algorithm mismatch.
func (r *ProviderRegistry) RegisterJWEEncryptor(alg string, p JWEEncryptProvider) {
	putProvider(r, r.jweEnc, "JWE encrypt provider", "OverrideJWEEncryptor", alg, p.KeyAlgorithm(), p, false)
}

// OverrideJWEEncryptor replaces (or adds) a JWEEncryptProvider for the given key algorithm.
func (r *ProviderRegistry) OverrideJWEEncryptor(alg string, p JWEEncryptProvider) {
	putProvider(r, r.jweEnc, "JWE encrypt provider", "OverrideJWEEncryptor", alg, p.KeyAlgorithm(), p, true)
}

// GetJWEEncryptor returns the registered JWEEncryptProvider for the key algorithm.
func (r *ProviderRegistry) GetJWEEncryptor(alg string) (JWEEncryptProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.jweEnc[alg]
	return p, ok
}

// RegisterJWEDecryptor registers a JWEDecryptProvider for the given key algorithm.
// It panics on duplicate registration or key/algorithm mismatch.
func (r *ProviderRegistry) RegisterJWEDecryptor(alg string, p JWEDecryptProvider) {
	putProvider(r, r.jweDec, "JWE decrypt provider", "OverrideJWEDecryptor", alg, p.KeyAlgorithm(), p, false)
}

// OverrideJWEDecryptor replaces (or adds) a JWEDecryptProvider for the given key algorithm.
func (r *ProviderRegistry) OverrideJWEDecryptor(alg string, p JWEDecryptProvider) {
	putProvider(r, r.jweDec, "JWE decrypt provider", "OverrideJWEDecryptor", alg, p.KeyAlgorithm(), p, true)
}

// GetJWEDecryptor returns the registered JWEDecryptProvider for the key algorithm.
func (r *ProviderRegistry) GetJWEDecryptor(alg string) (JWEDecryptProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.jweDec[alg]
	return p, ok
}

// RegisterContentEncryptor registers a ContentEncryptProvider for the given content encryption algorithm.
// It panics on duplicate registration or key/algorithm mismatch.
func (r *ProviderRegistry) RegisterContentEncryptor(alg string, p ContentEncryptProvider) {
	putProvider(r, r.contentEnc, "content encrypt provider", "OverrideContentEncryptor", alg, p.Algorithm(), p, false)
}

// OverrideContentEncryptor replaces (or adds) a ContentEncryptProvider for the given content encryption algorithm.
func (r *ProviderRegistry) OverrideContentEncryptor(alg string, p ContentEncryptProvider) {
	putProvider(r, r.contentEnc, "content encrypt provider", "OverrideContentEncryptor", alg, p.Algorithm(), p, true)
}

// GetContentEncryptor returns the registered ContentEncryptProvider for the content encryption algorithm.
func (r *ProviderRegistry) GetContentEncryptor(alg string) (ContentEncryptProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.contentEnc[alg]
	return p, ok
}

// RegisterContentDecryptor registers a ContentDecryptProvider for the given content encryption algorithm.
// It panics on duplicate registration or key/algorithm mismatch.
func (r *ProviderRegistry) RegisterContentDecryptor(alg string, p ContentDecryptProvider) {
	putProvider(r, r.contentDec, "content decrypt provider", "OverrideContentDecryptor", alg, p.Algorithm(), p, false)
}

// OverrideContentDecryptor replaces (or adds) a ContentDecryptProvider for the given content encryption algorithm.
func (r *ProviderRegistry) OverrideContentDecryptor(alg string, p ContentDecryptProvider) {
	putProvider(r, r.contentDec, "content decrypt provider", "OverrideContentDecryptor", alg, p.Algorithm(), p, true)
}

// GetContentDecryptor returns the registered ContentDecryptProvider for the content encryption algorithm.
func (r *ProviderRegistry) GetContentDecryptor(alg string) (ContentDecryptProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.contentDec[alg]
	return p, ok
}

// --- built-in software providers (registered to DefaultRegistry; HSM/KMS overrides in init()) ---

type stdSm2SignProvider struct{}

func (stdSm2SignProvider) Algorithm() string { return SGD_SM3_SM2 }

func (stdSm2SignProvider) Sign(ctx context.Context, keyID, tokenType string, key interface{}, payload []byte) (string, error) {
	priv, ok := key.(*gmsm.PrivateKey)
	if !ok {
		return "", fmt.Errorf("stdSm2SignProvider: expected *sm2.PrivateKey, got %T", key)
	}
	return signSM2(SGD_SM3_SM2, keyID, tokenType, priv, payload)
}

type sm2VerifyProvider struct{}

func (sm2VerifyProvider) Algorithm() string { return SGD_SM3_SM2 }

func (sm2VerifyProvider) Verify(ctx context.Context, signingInput, signature []byte, key interface{}) error {
	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("sm2VerifyProvider: expected *ecdsa.PublicKey, got %T", key)
	}
	h, err := GetHashAlgorithm(SGD_SM3_SM2)
	if err != nil {
		return fmt.Errorf("error getting SM3 hash: %w", err)
	}
	h.Write(signingInput)
	digest := h.Sum(nil)
	if !gm.SM2Verify(pubKey, digest, signature) {
		return fmt.Errorf("SM2 signature verification failed")
	}
	return nil
}

type stdSm9SignProvider struct{}

func (stdSm9SignProvider) Algorithm() string { return SGD_SM3_SM9 }

func (stdSm9SignProvider) Sign(_ context.Context, keyID, tokenType string, key interface{}, payload []byte) (string, error) {
	// SM9 requires the signer's uid. Signer.Sign always wraps the key material
	// in SM9SignKey, so that is the only accepted key type here.
	signKey, ok := key.(*SM9SignKey)
	if !ok {
		return "", fmt.Errorf("stdSm9SignProvider: expected *SM9SignKey, got %T", key)
	}
	if len(signKey.UID) == 0 {
		return "", fmt.Errorf("stdSm9SignProvider: SM9 signing requires uid; call Signer.SetSM9UID before signing")
	}
	return signSM9(SGD_SM3_SM9, keyID, tokenType, signKey.PrivateKey, signKey.UID, payload)
}

// SM9SignKey wraps the SM9 signing key material with the user identifier.
// It is passed as the key argument to stdSm9SignProvider.Sign.
type SM9SignKey struct {
	PrivateKey *sm9.SignPrivateKey
	UID        []byte
}

// SM9VerifyArgs holds the arguments needed for SM9 signature verification.
type SM9VerifyArgs struct {
	MasterPubKey *sm9.SignMasterPublicKey
	UID          []byte
}

type sm9VerifyProvider struct{}

func (sm9VerifyProvider) Algorithm() string { return SGD_SM3_SM9 }

func (sm9VerifyProvider) Verify(ctx context.Context, signingInput, signature []byte, key interface{}) error {
	args, ok := key.(SM9VerifyArgs)
	if !ok {
		return fmt.Errorf("sm9VerifyProvider: expected SM9VerifyArgs, got %T", key)
	}
	h, err := GetHashAlgorithm(SGD_SM3_SM9)
	if err != nil {
		return fmt.Errorf("error getting SM3 hash: %w", err)
	}
	h.Write(signingInput)
	digest := h.Sum(nil)
	if !gm.SM9Verify(args.MasterPubKey, args.UID, digest, signature) {
		return fmt.Errorf("SM9 signature verification failed")
	}
	return nil
}

type sm2JWEProvider struct{}

func (sm2JWEProvider) KeyAlgorithm() string      { return SGD_SM2_3 }
func (sm2JWEProvider) ContentEncryption() string { return SGD_SM4_GCM }

func (sm2JWEProvider) Encrypt(ctx context.Context, plaintext []byte, key interface{}) (string, error) {
	return std.EncryptSM2JWE(plaintext, key)
}

func (sm2JWEProvider) Decrypt(ctx context.Context, compact string, key interface{}) ([]byte, error) {
	return std.DecryptSM2JWE(compact, key)
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
	return std.EncryptSM9JWE(plaintext, masterPubKey, uid, SGD_SM4_GCM)
}

func (sm9JWEProvider) Decrypt(ctx context.Context, compact string, key interface{}) ([]byte, error) {
	decKey, ok := key.(*SM9DecryptKey)
	if !ok {
		return nil, fmt.Errorf("sm9JWEProvider: expected *SM9DecryptKey, got %T", key)
	}
	return std.DecryptSM9JWE(compact, decKey.PrivateKey, decKey.UID)
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

// --- built-in content encryption providers ---

type sm4GCMContentProvider struct{}

func (sm4GCMContentProvider) Algorithm() string { return SGD_SM4_GCM }

func (sm4GCMContentProvider) Encrypt(ctx context.Context, key, iv, plaintext, aad []byte) ([]byte, error) {
	return std.SM4GCMEncrypt(key, iv, plaintext, aad)
}

func (sm4GCMContentProvider) Decrypt(ctx context.Context, key, iv, sealed, aad []byte) ([]byte, error) {
	return std.SM4GCMDecrypt(key, iv, sealed, aad)
}

type aesGCMContentProvider struct {
	alg string
}

func (p aesGCMContentProvider) Algorithm() string { return p.alg }

func (aesGCMContentProvider) Encrypt(ctx context.Context, key, iv, plaintext, aad []byte) ([]byte, error) {
	return std.AESGCMEncrypt(key, iv, plaintext, aad)
}

func (aesGCMContentProvider) Decrypt(ctx context.Context, key, iv, sealed, aad []byte) ([]byte, error) {
	return std.AESGCMDecrypt(key, iv, sealed, aad)
}

type aesCBCContentProvider struct {
	alg string
}

func (p aesCBCContentProvider) Algorithm() string { return p.alg }

func (p aesCBCContentProvider) Encrypt(ctx context.Context, key, iv, plaintext, aad []byte) ([]byte, error) {
	return std.AESCBCEncrypt(p.alg, key, iv, plaintext, aad)
}

func (p aesCBCContentProvider) Decrypt(ctx context.Context, key, iv, sealed, aad []byte) ([]byte, error) {
	return std.AESCBCDecrypt(p.alg, key, iv, sealed, aad)
}

func init() {
	DefaultRegistry.RegisterSigner(SGD_SM3_SM2, stdSm2SignProvider{})
	DefaultRegistry.RegisterSigner(SGD_SM3_SM9, stdSm9SignProvider{})
	DefaultRegistry.RegisterVerifier(SGD_SM3_SM2, sm2VerifyProvider{})
	DefaultRegistry.RegisterVerifier(SGD_SM3_SM9, sm9VerifyProvider{})
	DefaultRegistry.RegisterJWEEncryptor(SGD_SM2_3, sm2JWEProvider{})
	DefaultRegistry.RegisterJWEEncryptor(SGD_SM9_3, sm9JWEProvider{})
	DefaultRegistry.RegisterJWEDecryptor(SGD_SM2_3, sm2JWEProvider{})
	DefaultRegistry.RegisterJWEDecryptor(SGD_SM9_3, sm9JWEProvider{})
	DefaultRegistry.RegisterContentEncryptor(SGD_SM4_GCM, sm4GCMContentProvider{})
	DefaultRegistry.RegisterContentDecryptor(SGD_SM4_GCM, sm4GCMContentProvider{})
	DefaultRegistry.RegisterContentEncryptor("A128GCM", aesGCMContentProvider{alg: "A128GCM"})
	DefaultRegistry.RegisterContentDecryptor("A128GCM", aesGCMContentProvider{alg: "A128GCM"})
	DefaultRegistry.RegisterContentEncryptor("A192GCM", aesGCMContentProvider{alg: "A192GCM"})
	DefaultRegistry.RegisterContentDecryptor("A192GCM", aesGCMContentProvider{alg: "A192GCM"})
	DefaultRegistry.RegisterContentEncryptor("A256GCM", aesGCMContentProvider{alg: "A256GCM"})
	DefaultRegistry.RegisterContentDecryptor("A256GCM", aesGCMContentProvider{alg: "A256GCM"})
	DefaultRegistry.RegisterContentEncryptor("A128CBC-HS256", aesCBCContentProvider{alg: "A128CBC-HS256"})
	DefaultRegistry.RegisterContentDecryptor("A128CBC-HS256", aesCBCContentProvider{alg: "A128CBC-HS256"})
	DefaultRegistry.RegisterContentEncryptor("A192CBC-HS384", aesCBCContentProvider{alg: "A192CBC-HS384"})
	DefaultRegistry.RegisterContentDecryptor("A192CBC-HS384", aesCBCContentProvider{alg: "A192CBC-HS384"})
	DefaultRegistry.RegisterContentEncryptor("A256CBC-HS512", aesCBCContentProvider{alg: "A256CBC-HS512"})
	DefaultRegistry.RegisterContentDecryptor("A256CBC-HS512", aesCBCContentProvider{alg: "A256CBC-HS512"})
}
