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
	"github.com/roidmc/kexcore-oidc/pkg/storm/shared"
)

// maxNonceCacheSize is the hard limit on the nonce replay cache.
// Prevents unbounded memory growth in high-traffic deployments.
// When exceeded, the oldest entries are evicted.
const maxNonceCacheSize = 10000

// Plugin implements DPoP proof validation and token binding.
type Plugin struct {
	mu         sync.Mutex
	usedNonces map[string]time.Time // jti replay detection
	stopCh     chan struct{}        // signals cleanup goroutine to stop
}

// NewWithConfig creates a new DPoP plugin.
func NewWithConfig() *Plugin {
	p := &Plugin{
		usedNonces: make(map[string]time.Time, maxNonceCacheSize),
		stopCh:     make(chan struct{}),
	}
	go p.cleanupLoop()
	return p
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

// ContextWithDPoP stores the DPoP proof in the request context.
// Uses shared context key for cross-package access.
func ContextWithDPoP(ctx context.Context, proof *Proof) context.Context {
	return shared.ContextWithDPoP(ctx, proof)
}

// DPoPFromContext retrieves the DPoP proof from the context as *Proof.
// Returns nil if no DPoP proof was presented.
// For cross-package access, use shared.DPoPFromContext() which returns
// the shared.DPoPProof interface.
func DPoPFromContext(ctx context.Context) *Proof {
	proof, _ := shared.DPoPFromContext(ctx).(*Proof)
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
		// Evict oldest entries if cache is at capacity
		if len(p.usedNonces) >= maxNonceCacheSize {
			p.evictOldestLocked()
		}
		p.usedNonces[proof.UniqueID] = time.Now()
		p.mu.Unlock()

		ctx := ContextWithDPoP(r.Context(), proof)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// evictOldestLocked removes the oldest ~25% of entries.
// Must be called with p.mu held.
func (p *Plugin) evictOldestLocked() {
	// Find the 25th percentile time — evict everything older
	target := maxNonceCacheSize / 4
	if target == 0 {
		target = 1
	}

	// Collect all timestamps
	oldest := make([]time.Time, 0, len(p.usedNonces))
	for _, t := range p.usedNonces {
		oldest = append(oldest, t)
	}
	if len(oldest) < target {
		return
	}

	// Partial sort to find the target-th oldest
	for i := 0; i < target; i++ {
		for j := i + 1; j < len(oldest); j++ {
			if oldest[j].Before(oldest[i]) {
				oldest[i], oldest[j] = oldest[j], oldest[i]
			}
		}
	}
	cutoff := oldest[target-1]

	for jti, t := range p.usedNonces {
		if !t.After(cutoff) {
			delete(p.usedNonces, jti)
		}
	}
}

// CleanupNonceCache removes expired nonces from the cache.
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

// cleanupLoop runs periodic nonce cache cleanup.
func (p *Plugin) cleanupLoop() {
	ticker := time.NewTicker(MaxProofAge)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.CleanupNonceCache()
		case <-p.stopCh:
			return
		}
	}
}

// Stop terminates the background cleanup goroutine.
func (p *Plugin) Stop() {
	select {
	case <-p.stopCh:
	default:
		close(p.stopCh)
	}
}
