// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op_test

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/v1/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/v1/pkg/op"
	"github.com/roidmc/kexcore-oidc/v1/pkg/op/mock"
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
		mk.EXPECT().Algorithm().Return("RS256")
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
}
