// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKeyWithID(t *testing.T, kid string) (jwk.Key, jwk.Key) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privJWK, err := jwk.Import[jwk.Key](privKey)
	require.NoError(t, err)
	err = privJWK.Set(jwk.KeyIDKey, kid)
	require.NoError(t, err)
	err = privJWK.Set(jwk.KeyUsageKey, jwk.ForSignature)
	require.NoError(t, err)
	err = privJWK.Set(jwk.AlgorithmKey, jwa.RS256())
	require.NoError(t, err)

	pubJWK, err := privJWK.PublicKey()
	require.NoError(t, err)

	return privJWK, pubJWK
}

func generateTestKey(t *testing.T) (jwk.Key, jwk.Key) {
	return generateTestKeyWithID(t, "test-key-1")
}

func createJWKSet(keys ...jwk.Key) jwk.Set {
	set := jwk.NewSet()
	for _, key := range keys {
		set.AddKey(key)
	}
	return set
}

func signToken(t *testing.T, privKey jwk.Key, kid string) []byte {
	t.Helper()

	payload := []byte(`{"sub":"test-user","iss":"https://example.com"}`)
	alg := jwa.RS256()

	if kid != "" {
		headers := jws.NewHeaders()
		_ = headers.Set(jws.AlgorithmKey, alg)
		_ = headers.Set(jws.KeyIDKey, kid)
		signed, err := jws.Sign(payload, jws.WithKey(alg, privKey, jws.WithProtectedHeaders(headers)))
		require.NoError(t, err)
		return signed
	}

	signed, err := jws.Sign(payload, jws.WithKey(alg, privKey))
	require.NoError(t, err)
	return signed
}

func newTestRemoteKeySet(keys jwk.Set, opts ...func(*remoteKeySet)) *remoteKeySet {
	set := &remoteKeySet{
		httpClient: http.DefaultClient,
		jwksURL:    "https://example.com/jwks",
	}
	set.cachedKeys = keys
	for _, opt := range opts {
		opt(set)
	}
	return set
}

func TestNewRemoteKeySet(t *testing.T) {
	client := &http.Client{}
	url := "https://example.com/jwks"

	set := NewRemoteKeySet(client, url)
	assert.NotNil(t, set)

	remoteSet, ok := set.(*remoteKeySet)
	require.True(t, ok)
	assert.Equal(t, client, remoteSet.httpClient)
	assert.Equal(t, url, remoteSet.jwksURL)
	assert.False(t, remoteSet.skipRemoteCheck)
	assert.Nil(t, remoteSet.cachedKeys)
}

func TestSkipRemoteCheck(t *testing.T) {
	set := &remoteKeySet{}
	opt := SkipRemoteCheck()
	opt(set)
	assert.True(t, set.skipRemoteCheck)
}

func TestExactMatch(t *testing.T) {
	tests := []struct {
		name            string
		jwkID           string
		jwsID           string
		skipRemoteCheck bool
		want            bool
	}{
		{
			name:  "both empty, skip false",
			jwkID: "",
			jwsID: "",
			want:  false,
		},
		{
			name:            "both empty, skip true",
			jwkID:           "",
			jwsID:           "",
			skipRemoteCheck: true,
			want:            true,
		},
		{
			name:  "matching ids",
			jwkID: "key1",
			jwsID: "key1",
			want:  true,
		},
		{
			name:  "different ids",
			jwkID: "key1",
			jwsID: "key2",
			want:  false,
		},
		{
			name:  "jwk empty, jws not",
			jwkID: "",
			jwsID: "key1",
			want:  false,
		},
		{
			name:  "jwk not empty, jws empty",
			jwkID: "key1",
			jwsID: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := &remoteKeySet{skipRemoteCheck: tt.skipRemoteCheck}
			got := set.exactMatch(tt.jwkID, tt.jwsID)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKeysFromCache(t *testing.T) {
	privKey, pubKey := generateTestKey(t)
	set := newTestRemoteKeySet(createJWKSet(pubKey))

	keys := set.keysFromCache()
	assert.NotNil(t, keys)
	assert.Equal(t, 1, keys.Len())

	_, _ = privKey, pubKey
}

func TestKeysFromCacheEmpty(t *testing.T) {
	set := newTestRemoteKeySet(nil)
	keys := set.keysFromCache()
	assert.Nil(t, keys)
}

func TestVerifySignatureCached(t *testing.T) {
	privKey, pubKey := generateTestKey(t)
	set := newTestRemoteKeySet(createJWKSet(pubKey))

	token := signToken(t, privKey, "test-key-1")

	jwsMsg, err := jws.Parse(token)
	require.NoError(t, err)

	keyID, alg := getKeyIDAndAlg(jwsMsg)
	payload, err := set.verifySignatureCached(token, jwsMsg, keyID, alg)
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestVerifySignatureCachedNoKeys(t *testing.T) {
	set := newTestRemoteKeySet(nil)

	token := []byte("invalid")
	jwsMsg := &jws.Message{}

	payload, err := set.verifySignatureCached(token, jwsMsg, "", "RS256")
	assert.NoError(t, err)
	assert.Nil(t, payload)
}

func TestVerifySignatureCachedWrongKey(t *testing.T) {
	_, pubKey := generateTestKey(t)
	set := newTestRemoteKeySet(createJWKSet(pubKey))

	privKey2, _ := generateTestKeyWithID(t, "test-key-2")
	token := signToken(t, privKey2, "test-key-2")

	jwsMsg, err := jws.Parse(token)
	require.NoError(t, err)

	keyID, alg := getKeyIDAndAlg(jwsMsg)
	payload, err := set.verifySignatureCached(token, jwsMsg, keyID, alg)
	assert.NoError(t, err)
	assert.Nil(t, payload)
}

func TestVerifySignature(t *testing.T) {
	privKey, pubKey := generateTestKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set := createJWKSet(pubKey)
		data, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()

	set := NewRemoteKeySet(server.Client(), server.URL+"/jwks")
	token := signToken(t, privKey, "test-key-1")

	payload, err := set.VerifySignature(context.Background(), token)
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestVerifySignatureCachedHit(t *testing.T) {
	privKey, pubKey := generateTestKey(t)
	set := newTestRemoteKeySet(createJWKSet(pubKey))

	token := signToken(t, privKey, "test-key-1")

	payload, err := set.VerifySignature(context.Background(), token)
	require.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestVerifySignatureRemoteFetch(t *testing.T) {
	privKey, pubKey := generateTestKey(t)

	var mu sync.Mutex
	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetchCount++
		mu.Unlock()

		set := createJWKSet(pubKey)
		data, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()

	set := NewRemoteKeySet(server.Client(), server.URL+"/jwks")
	token := signToken(t, privKey, "test-key-1")

	payload, err := set.VerifySignature(context.Background(), token)
	require.NoError(t, err)
	assert.NotNil(t, payload)

	mu.Lock()
	assert.Equal(t, 1, fetchCount)
	mu.Unlock()
}

func TestKeysFromRemote(t *testing.T) {
	_, pubKey := generateTestKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set := createJWKSet(pubKey)
		data, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()

	set := &remoteKeySet{
		httpClient: server.Client(),
		jwksURL:    server.URL + "/jwks",
	}

	keys, err := set.keysFromRemote(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, keys)
	assert.Equal(t, 1, keys.Len())
}

func TestKeysFromRemoteError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	set := &remoteKeySet{
		httpClient: server.Client(),
		jwksURL:    server.URL + "/jwks",
	}

	_, err := set.keysFromRemote(context.Background())
	assert.Error(t, err)
}

func TestKeysFromRemoteContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer server.Close()

	set := &remoteKeySet{
		httpClient: server.Client(),
		jwksURL:    server.URL + "/jwks",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := set.keysFromRemote(ctx)
	assert.Error(t, err)
}

func TestKeysFromRemoteConcurrent(t *testing.T) {
	_, pubKey := generateTestKey(t)

	var mu sync.Mutex
	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetchCount++
		mu.Unlock()

		set := createJWKSet(pubKey)
		data, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()

	set := &remoteKeySet{
		httpClient: server.Client(),
		jwksURL:    server.URL + "/jwks",
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys, err := set.keysFromRemote(context.Background())
			assert.NoError(t, err)
			assert.NotNil(t, keys)
		}()
	}
	wg.Wait()

	mu.Lock()
	assert.Equal(t, 1, fetchCount)
	mu.Unlock()
}

func getKeyIDAndAlg(jwsMsg *jws.Message) (string, string) {
	keyID := ""
	alg := ""
	for _, sig := range jwsMsg.Signatures() {
		keyID, _ = sig.ProtectedHeaders().KeyID()
		sigAlg, _ := sig.ProtectedHeaders().Algorithm()
		alg = sigAlg.String()
		break
	}
	return keyID, alg
}
