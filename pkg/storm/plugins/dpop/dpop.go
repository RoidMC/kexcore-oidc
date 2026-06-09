// Package dpop implements Demonstrating Proof-of-Possession (DPoP)
// at the application layer (RFC 9449).
//
// It provides:
//   - DPoP proof validation (Section 4.1, 4.2, 4.3)
//   - DPoP-bound access token creation (Section 7.1, cnf.jkt)
//   - DPoP proof verification for resource server introspection (Section 10.1)
package dpop

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// Plugin implements DPoP proof validation and token binding.
type Plugin struct {
	mu         sync.Mutex
	usedNonces map[string]time.Time // jti replay detection
}

// NewWithConfig creates a new DPoP plugin.
func NewWithConfig() *Plugin {
	return &Plugin{
		usedNonces: make(map[string]time.Time),
	}
}

// init self-registers the DPoP plugin in the global registry.
func init() {
	storm.RegisterPlugin("dpop", storm.PriorityDPoP, func(ctx *storm.PluginContext) storm.Plugin {
		return NewWithConfig()
	})
}

// Category returns CategoryStandard — DPoP is optional.
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

// Requires returns no storage dependencies (DPoP is stateless except nonce cache).
func (p *Plugin) Requires() []string { return nil }

// Name returns the plugin name.
func (p *Plugin) Name() string { return "dpop" }

// Register is a no-op for the DPoP plugin.
func (p *Plugin) Register(r chi.Router) {}

// Contribute returns discovery fields for DPoP.
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.Extra["dpop_signing_alg_values_supported"] = []string{"ES256", "RS256"}
}

// --- Context helpers ---

type dpopContextKey struct{}

// ContextWithDPoP stores the DPoP proof in the request context.
func ContextWithDPoP(ctx context.Context, proof *Proof) context.Context {
	return context.WithValue(ctx, dpopContextKey{}, proof)
}

// DPoPFromContext retrieves the DPoP proof from the context.
// Returns nil if no DPoP proof was presented.
func DPoPFromContext(ctx context.Context) *Proof {
	proof, _ := ctx.Value(dpopContextKey{}).(*Proof)
	return proof
}

// --- Middleware ---

// Middleware parses the DPoP header from the request and stores the
// proof in the request context. If no DPoP header is present, the
// context value is nil.
func (p *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dpopHeader := r.Header.Get(Header)
		if dpopHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		proof, err := ParseProof(dpopHeader, r.Method, r.URL.String())
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Nonce replay detection
		p.mu.Lock()
		if _, exists := p.usedNonces[proof.UniqueID]; exists {
			p.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}
		p.usedNonces[proof.UniqueID] = time.Now()
		p.mu.Unlock()

		ctx := ContextWithDPoP(r.Context(), proof)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CleanupNonceCache removes expired nonces from the cache.
// Should be called periodically to prevent memory leaks.
func (p *Plugin) CleanupNonceCache() {
	p.mu.Lock()
	defer p.mu.Unlock()
	cutoff := time.Now().Add(-MaxProofAge)
	for jti, t := range p.usedNonces {
		if t.Before(cutoff) {
			delete(p.usedNonces, jti)
		}
	}
}
