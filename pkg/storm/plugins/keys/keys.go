// Package keys implements the JWKS (JSON Web Key Set) endpoint plugin.
package keys

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

// Plugin serves the JWKS endpoint.
type Plugin struct {
	store           storm.KeyStore
	endpointConfigs shared.EndpointConfigMap // endpoint configurations (optional)
}

// New creates a new Keys plugin from a PluginContext.
func New(ctx *storm.PluginContext) *Plugin {
	return &Plugin{
		store:           ctx.Storage.(storm.KeyStore),
		endpointConfigs: ctx.EndpointConfigs,
	}
}

// NewWithStore creates a new Keys plugin with an explicit KeyStore.
func NewWithStore(store storm.KeyStore) *Plugin {
	return &Plugin{store: store}
}

// init self-registers the keys plugin in the global registry.
func init() {
	storm.RegisterPlugin("keys", storm.PriorityKeys, func(ctx *storm.PluginContext) storm.Plugin {
		return New(ctx)
	})
}

// Category returns CategoryCore — JWKS is a required OIDC endpoint.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryCore }

// Requires returns the storage dependencies.
func (p *Plugin) Requires() []string { return []string{"KeyStore"} }

// Name returns the plugin name.
func (p *Plugin) Name() string { return "keys" }

// Register installs the JWKS route.
func (p *Plugin) Register(r chi.Router) {
	keysPath := p.getRoutePath("keys", "/.well-known/jwks.json")
	r.Get(keysPath, p.handle)
}

// Contribute returns the discovery fields for the JWKS endpoint.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.JWKSURI = p.resolveEndpoint(ctx, "keys", "/.well-known/jwks.json")
}

// resolveEndpoint resolves the absolute URL for the given endpoint.
// If EndpointConfigs is configured, it uses that; otherwise it falls back
// to the default behavior of building the URL from the issuer in context.
func (p *Plugin) resolveEndpoint(ctx context.Context, endpointName, defaultPath string) string {
	if p.endpointConfigs != nil {
		defaultURL := shared.EndpointURL(ctx, protocol.NewEndpoint(defaultPath))
		return p.endpointConfigs.GetDiscoveryURL(endpointName, defaultURL)
	}
	return shared.EndpointURL(ctx, protocol.NewEndpoint(defaultPath))
}

// getRoutePath returns the route path for the given endpoint.
func (p *Plugin) getRoutePath(endpointName, defaultPath string) string {
	if p.endpointConfigs != nil {
		return p.endpointConfigs.GetRoutePath(endpointName, defaultPath)
	}
	return defaultPath
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	keys, err := p.store.KeySet(r.Context())
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}

	// injectCertFields injects x5c, x5t (SHA-1), x5t#S256 (SHA-256) into a raw JSON key.
	// Returns the updated raw JSON.
	injectCertFields := func(raw json.RawMessage, certs [][]byte) json.RawMessage {
		if len(certs) == 0 {
			return raw
		}
		// Build x5c array: base64-encoded DER certificates per RFC 7517 §4.7
		x5c := make([]string, len(certs))
		for i, c := range certs {
			x5c[i] = base64.StdEncoding.EncodeToString(c)
		}

		// x5t: SHA-1 thumbprint per RFC 7517 §4.8
		var x5t string
		if len(certs[0]) > 0 {
			h := sha1.Sum(certs[0])
			x5t = base64.RawURLEncoding.EncodeToString(h[:])
		}

		// x5t#S256: SHA-256 thumbprint per RFC 7517 §4.9
		var x5tS256 string
		if len(certs[0]) > 0 {
			h := sha256.Sum256(certs[0])
			x5tS256 = base64.RawURLEncoding.EncodeToString(h[:])
		}

		// Unmarshal into map, inject fields, re-marshal — avoids manual JSON string concatenation.
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return raw
		}
		x5cJSON, _ := json.Marshal(x5c)
		x5tJSON, _ := json.Marshal(x5t)
		x5tS256JSON, _ := json.Marshal(x5tS256)
		m["x5c"] = x5cJSON
		m["x5t"] = x5tJSON
		m["x5t#S256"] = x5tS256JSON
		out, err := json.Marshal(m)
		if err != nil {
			return raw
		}
		return out
	}

	// Build the JWKS response, handling both standard and GM/T keys.
	// Standard keys use jwk.Set; GM/T keys are serialized via GMJWK.
	type jwksResponse struct {
		Keys []json.RawMessage `json:"keys"`
	}

	resp := jwksResponse{Keys: make([]json.RawMessage, 0, len(keys))}

	for _, k := range keys {
		// Prefer GM/T JWK representation for national cryptography keys.
		// GM/T keys satisfy protocol.GMJWKProvider optionally.
		if gm, ok := k.(protocol.GMJWKProvider); ok && gm.GMJWK() != nil {
			raw, err := gm.GMJWK().MarshalJSON()
			if err != nil {
				shared.WriteError(w, r, err, nil)
				return
			}
			// Inject x5c, x5t, x5t#S256 if the key provides a certificate chain
			if cp, ok := k.(protocol.CertificateProvider); ok {
				if certs, err := cp.CertificateChain(); err == nil && len(certs) > 0 {
					raw = injectCertFields(raw, certs)
				}
			}
			resp.Keys = append(resp.Keys, raw)
			continue
		}

		// Standard key (RSA, ECDSA, EdDSA)
		jwkKey := k.Key()
		if jwkKey == nil {
			continue
		}
		// Extract public key only — JWKS must never expose private key material.
		pubKey, err := jwkKey.PublicKey()
		if err != nil {
			shared.WriteError(w, r, err, nil)
			return
		}
		// PublicKey() in jwx does not preserve non-intrinsic fields (use, kid, alg).
		// Copy them from the original key so the JWKS response includes "use":"sig" etc.
		if v, ok := jwkKey.KeyUsage(); ok {
			_ = pubKey.Set(jwk.KeyUsageKey, v)
		}
		if v, ok := jwkKey.KeyID(); ok {
			_ = pubKey.Set(jwk.KeyIDKey, v)
		}
		if v, ok := jwkKey.Algorithm(); ok {
			_ = pubKey.Set(jwk.AlgorithmKey, v)
		}
		raw, err := json.Marshal(pubKey)
		if err != nil {
			shared.WriteError(w, r, err, nil)
			return
		}
		// Inject x5c, x5t, x5t#S256 if the key provides a certificate chain
		if cp, ok := k.(protocol.CertificateProvider); ok {
			if certs, err := cp.CertificateChain(); err == nil && len(certs) > 0 {
				raw = injectCertFields(raw, certs)
			}
		}
		resp.Keys = append(resp.Keys, raw)
	}

	// RFC 7517 §5: JWKS is public data, safe to cache.
	// Only set caching headers on success — errors use WriteError which has its own semantics.
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "application/json")

	out, err := json.Marshal(resp)
	if err != nil {
		shared.WriteError(w, r, err, nil)
		return
	}
	w.Write(out)
}
