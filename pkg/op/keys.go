// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"

	"github.com/emmansun/gmsm/sm9"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/roidmc/kexcore-oidc/v1/pkg/crypto"
	httphelper "github.com/roidmc/kexcore-oidc/v1/pkg/http"
)

type KeyProvider interface {
	KeySet(context.Context) ([]Key, error)
}

func keysHandler(k KeyProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Keys(w, r, k)
	}
}

func Keys(w http.ResponseWriter, r *http.Request, k KeyProvider) {
	ctx, span := Tracer.Start(r.Context(), "Keys")
	r = r.WithContext(ctx)
	defer span.End()

	keySet, err := k.KeySet(r.Context())
	if err != nil {
		httphelper.MarshalJSONWithStatus(w, err, http.StatusInternalServerError)
		return
	}
	httphelper.MarshalJSON(w, jsonWebKeySet(keySet))
}

// jwksResponse is the JSON structure for a JWKS endpoint response.
type jwksResponse struct {
	Keys []map[string]interface{} `json:"keys"`
}

func jsonWebKeySet(keys []Key) jwksResponse {
	resp := jwksResponse{Keys: make([]map[string]interface{}, 0, len(keys))}
	for _, key := range keys {
		// SM2 keys require manual JWK construction because jwx does not
		// recognize the SM2 curve. Build the JWK per GM/T 0125.4-2022.
		if crypto.IsSM2Algorithm(key.Algorithm()) {
			jwkMap := buildSM2JWKMap(key)
			if jwkMap != nil {
				resp.Keys = append(resp.Keys, jwkMap)
			}
			continue
		}

		// SM9 keys require manual JWK construction (identity-based cryptography).
		if crypto.IsSM9Algorithm(key.Algorithm()) {
			jwkMap := buildSM9JWKMap(key)
			if jwkMap != nil {
				resp.Keys = append(resp.Keys, jwkMap)
			}
			continue
		}

		k, err := jwk.Import[jwk.Key](key.Key())
		if err != nil {
			continue
		}
		if id := key.ID(); id != "" {
			_ = k.Set(jwk.KeyIDKey, id)
		}
		if alg := key.Algorithm(); alg != "" {
			_ = k.Set(jwk.AlgorithmKey, alg)
		}
		if use := key.Use(); use != "" {
			_ = k.Set(jwk.KeyUsageKey, use)
		}

		// Serialize the jwk.Key to JSON and back to map for uniform output
		raw, err := json.Marshal(k)
		if err != nil {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		resp.Keys = append(resp.Keys, m)
	}
	return resp
}

// buildSM2JWKMap constructs a JWK map for an SM2 public key per GM/T 0125.4-2022.
func buildSM2JWKMap(key Key) map[string]interface{} {
	pubKey, ok := key.Key().(*ecdsa.PublicKey)
	if !ok {
		return nil
	}

	sm2jwk := crypto.NewSM2JWK(pubKey, key.ID(), key.Use())

	// Marshal and unmarshal to get a map[string]interface{}
	raw, err := json.Marshal(sm2jwk)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

// buildSM9JWKMap constructs a JWK map for an SM9 signing master public key.
func buildSM9JWKMap(key Key) map[string]interface{} {
	masterPubKey, ok := key.Key().(*sm9.SignMasterPublicKey)
	if !ok {
		return nil
	}

	sm9jwk, err := crypto.NewSM9SignJWK(masterPubKey, key.ID(), key.Use())
	if err != nil {
		return nil
	}

	raw, err := json.Marshal(sm9jwk)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}
