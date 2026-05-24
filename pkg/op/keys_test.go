// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/crypto"
	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/op"
	"github.com/roidmc/kexcore-oidc/pkg/op/mock"
)

func TestKeys(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		m := mock.NewMockKeyProvider(ctrl)
		mk := mock.NewMockKey(ctrl)

		priv, err := rsa.GenerateKey(nil, 2048)
		require.NoError(t, err)
		pubKey := &priv.PublicKey

		mk.EXPECT().Key().Return(pubKey)
		mk.EXPECT().ID().Return("id")
		mk.EXPECT().Algorithm().Return("RS256").AnyTimes()
		mk.EXPECT().Use().Return("sig")
		m.EXPECT().KeySet(gomock.Any()).Return([]op.Key{mk}, nil)

		w := httptest.NewRecorder()
		op.Keys(w, httptest.NewRequest("GET", "/keys", nil), m)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Equal(t, "application/json", w.Header().Get("content-type"))

		// Parse response and verify key fields
		set, err := jwk.Parse(w.Body.Bytes())
		require.NoError(t, err)
		assert.Equal(t, 1, set.Len())
		key, ok := set.Key(0)
		require.True(t, ok)
		kid, _ := key.KeyID()
		assert.Equal(t, "id", kid)
		alg, _ := key.Algorithm()
		assert.Equal(t, "RS256", alg.String())
		use, _ := key.KeyUsage()
		assert.Equal(t, "sig", use)
	})

	t.Run("error", func(t *testing.T) {
		m := mock.NewMockKeyProvider(gomock.NewController(t))
		m.EXPECT().KeySet(gomock.Any()).Return(nil, oidc.ErrServerError())

		w := httptest.NewRecorder()
		op.Keys(w, httptest.NewRequest("GET", "/keys", nil), m)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Equal(t, "application/json", w.Header().Get("content-type"))
		assert.JSONEq(t, `{"error":"server_error"}`, w.Body.String())
	})

	t.Run("empty list", func(t *testing.T) {
		m := mock.NewMockKeyProvider(gomock.NewController(t))
		m.EXPECT().KeySet(gomock.Any()).Return(nil, nil)

		w := httptest.NewRecorder()
		op.Keys(w, httptest.NewRequest("GET", "/keys", nil), m)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Equal(t, "application/json", w.Header().Get("content-type"))
		assert.JSONEq(t, `{"keys":[]}`, w.Body.String())
	})

	t.Run("sm2 key with SM2-P-256 curve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		m := mock.NewMockKeyProvider(ctrl)
		mk := mock.NewMockKey(ctrl)

		priv, err := sm2.GenerateKey(rand.Reader)
		require.NoError(t, err)
		pubKey := priv.Public().(*ecdsa.PublicKey)

		mk.EXPECT().Key().Return(pubKey)
		mk.EXPECT().ID().Return("sm2-key-1")
		mk.EXPECT().Algorithm().Return(crypto.SGD_SM3_SM2).AnyTimes()
		mk.EXPECT().Use().Return("sig")
		m.EXPECT().KeySet(gomock.Any()).Return([]op.Key{mk}, nil)

		w := httptest.NewRecorder()
		op.Keys(w, httptest.NewRequest("GET", "/keys", nil), m)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		// Parse response as raw JSON since jwx cannot parse SM2 JWKs
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		keysRaw, ok := result["keys"]
		require.True(t, ok)
		keysArr, ok := keysRaw.([]interface{})
		require.True(t, ok)
		require.Len(t, keysArr, 1)
		sm2Key, ok := keysArr[0].(map[string]interface{})
		require.True(t, ok)

		// GM/T 0125.4-2022: SM2 keys must have crv set to "SM2-P-256"
		assert.Equal(t, "SM2-P-256", sm2Key["crv"], "SM2 key crv must be SM2-P-256 per GM/T 0125.4-2022")
		assert.Equal(t, "EC", sm2Key["kty"])
		assert.Equal(t, "sm2-key-1", sm2Key["kid"])
		assert.Equal(t, crypto.SGD_SM3_SM2, sm2Key["alg"])
		assert.Equal(t, "sig", sm2Key["use"])
		assert.NotNil(t, sm2Key["x"], "x coordinate must be present")
		assert.NotNil(t, sm2Key["y"], "y coordinate must be present")
	})
}
