// Package keys implements the JWKS (JSON Web Key Set) endpoint plugin.
package keys

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/storm"
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// Plugin serves the JWKS endpoint.
type Plugin struct {
	store storm.KeyStore
}

// New creates a new Keys plugin backed by the given KeyStore.
func New(store storm.KeyStore) *Plugin {
	return &Plugin{store: store}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "keys" }

// Register installs the JWKS route.
func (p *Plugin) Register(r chi.Router) {
	r.Get("/.well-known/jwks.json", p.handle)
}

// Contribute returns the discovery fields for the JWKS endpoint.
func (p *Plugin) Contribute(ctx context.Context) map[string]any {
	return map[string]any{
		"jwks_uri": shared.IssuerURL(ctx, "/.well-known/jwks.json"),
	}
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	keys, err := p.store.KeySet(r.Context())
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	// Build the JWKS response, handling both standard and GM/T keys.
	// Standard keys use jwk.Set; GM/T keys are serialized via GMJWK.
	type jwksResponse struct {
		Keys []json.RawMessage `json:"keys"`
	}

	resp := jwksResponse{Keys: make([]json.RawMessage, 0, len(keys))}

	for _, k := range keys {
		// Prefer GM/T JWK representation for national cryptography keys
		if gmJWK := k.GMJWK(); gmJWK != nil {
			raw, err := gmJWK.MarshalJSON()
			if err != nil {
				shared.WriteError(w, r, err, nil)
				return
			}
			resp.Keys = append(resp.Keys, raw)
			continue
		}

		// Standard key (RSA, ECDSA, EdDSA)
		jwkKey := k.Key()
		if jwkKey == nil {
			continue
		}
		raw, err := json.Marshal(jwkKey)
		if err != nil {
			shared.WriteError(w, r, err, nil)
			return
		}
		resp.Keys = append(resp.Keys, raw)
	}

	shared.JSONResponse(w, resp, http.StatusOK)
}
