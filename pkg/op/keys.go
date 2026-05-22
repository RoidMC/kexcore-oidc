// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op

import (
	"context"
	"net/http"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"

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

func jsonWebKeySet(keys []Key) jwk.Set {
	webKeys := jwk.NewSet()
	for _, key := range keys {
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
		_ = webKeys.AddKey(k)
	}
	return webKeys
}

// Deprecated: keyTypeFromAlg is no longer needed with jwx v4,
// which infers kty automatically via jwk.Import.
// Kept for reference only.
func keyTypeFromAlg(alg string) string {
	switch {
	case len(alg) >= 2 && (alg[:2] == "RS" || alg[:2] == "PS"):
		return "RSA"
	case len(alg) >= 2 && alg[:2] == "ES":
		return "EC"
	case alg == "EdDSA":
		return "OKP"
	case alg == "SM2":
		return "EC"
	default:
		return ""
	}
}

// Ensure jwa import is used
var _ = jwa.RSA()
