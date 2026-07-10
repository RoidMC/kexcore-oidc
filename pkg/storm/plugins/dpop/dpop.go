// Package dpop implements Demonstrating Proof-of-Possession (DPoP)
// at the application layer (RFC 9449).
//
// It provides:
//   - DPoP proof validation (Section 4.1, 4.2, 4.3)
//   - DPoP-bound access token creation (Section 7.1, cnf.jkt)
//   - DPoP proof verification for resource server introspection (Section 10.1)
//   - Server-provided nonce support (Section 8.1)
package dpop

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

// maxNonceCacheSize is the hard limit on the nonce replay cache.
// Prevents unbounded memory growth in high-traffic deployments.
// When exceeded, the oldest entries are evicted.
const maxNonceCacheSize = 10000

// NonceLifetime is the lifetime of a server-provided nonce (RFC 9449 §8.1).
const NonceLifetime = 5 * time.Minute

// NonceHeader is the HTTP header name for the DPoP nonce.
const NonceHeader = "DPoP-Nonce"

// Plugin implements DPoP proof validation and token binding.
type Plugin struct {
	mu         sync.Mutex
	usedNonces map[string]time.Time // jti replay detection
	nonces     map[string]time.Time // server-provided nonces
	stopCh     chan struct{}        // signals cleanup goroutine to stop
}

// NewWithConfig creates a new DPoP plugin.
func NewWithConfig() *Plugin {
	p := &Plugin{
		usedNonces: make(map[string]time.Time, maxNonceCacheSize),
		nonces:     make(map[string]time.Time, maxNonceCacheSize),
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
// context value is nil. If a DPoP header is present but invalid,
// the request is rejected with HTTP 400 (RFC 9449 §4.3).
func (p *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFC 9449 §7.1: if more than one DPoP proof is present, reject.
		dpopHeaders := r.Header.Values(Header)
		if len(dpopHeaders) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if len(dpopHeaders) > 1 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_dpop_proof","error_description":"multiple DPoP proofs in request"}`))
			return
		}
		dpopHeader := dpopHeaders[0]

		// Construct full URL from request (r.URL is relative in Go).
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		fullURL := scheme + "://" + r.Host + r.URL.String()

		proof, err := ParseProof(dpopHeader, r.Method, fullURL)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_dpop_proof","error_description":"` + escapeJSON(err.Error()) + `"}`))
			return
		}

		// Nonce replay detection + insert.
		// The eviction sort is done outside the lock to reduce contention.
		needEvict := false
		p.mu.Lock()
		if _, exists := p.usedNonces[proof.UniqueID]; exists {
			p.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_dpop_proof","error_description":"DPoP proof jti replay detected"}`))
			return
		}
		if len(p.usedNonces) >= maxNonceCacheSize {
			needEvict = true
		}
		p.usedNonces[proof.UniqueID] = time.Now()
		p.mu.Unlock()

		// Eviction sort happens outside the lock.
		if needEvict {
			p.evictBatch()
		}

		ctx := ContextWithDPoP(r.Context(), proof)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// entry is a snapshot of a nonce entry, used for eviction without holding the lock.
type entry struct {
	jti string
	t   time.Time
}

// evictBatch evicts the oldest ~25% of usedNonces entries.
// It copies the map, releases the lock, sorts, then re-acquires the lock to delete.
// This keeps the critical section short — sorting O(n log n) happens lock-free.
func (p *Plugin) evictBatch() {
	const evictRatio = 4 // evict oldest 1/4

	// ── Phase 1: copy under lock ───────────────────────────────────
	p.mu.Lock()
	snapshots := make([]entry, 0, len(p.usedNonces))
	for jti, t := range p.usedNonces {
		snapshots = append(snapshots, entry{jti, t})
	}
	p.mu.Unlock()

	// ── Phase 2: sort + select victims (lock-free) ──────────────────
	target := len(snapshots) / evictRatio
	if target == 0 {
		return
	}
	slices.SortFunc(snapshots, func(a, b entry) int {
		if a.t.Before(b.t) {
			return -1
		}
		if a.t.After(b.t) {
			return 1
		}
		return 0
	})
	cutoff := snapshots[target-1].t

	toDelete := make(map[string]struct{}, target)
	for i := 0; i < target; i++ {
		if !snapshots[i].t.After(cutoff) {
			toDelete[snapshots[i].jti] = struct{}{}
		}
	}

	// ── Phase 3: delete under lock ─────────────────────────────────
	p.mu.Lock()
	for jti := range toDelete {
		delete(p.usedNonces, jti)
	}
	p.mu.Unlock()
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
	// Also cleanup expired server-provided nonces
	nonceCutoff := time.Now().Add(-NonceLifetime)
	for nonce, t := range p.nonces {
		if t.Before(nonceCutoff) {
			delete(p.nonces, nonce)
		}
	}
}

// GenerateNonce creates a new server-provided nonce (RFC 9449 §8.1).
// The nonce is cached and can be validated later.
func (p *Plugin) GenerateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	nonce := base64.RawURLEncoding.EncodeToString(b)

	p.mu.Lock()
	needEvict := len(p.nonces) >= maxNonceCacheSize
	p.mu.Unlock()

	if needEvict {
		p.evictNoncesBatch()
	}

	p.mu.Lock()
	p.nonces[nonce] = time.Now()
	p.mu.Unlock()

	return nonce
}

// ValidateNonce validates a server-provided nonce (RFC 9449 §8.1).
// Returns true if the nonce is valid and not expired.
// The nonce is consumed (deleted) after validation.
func (p *Plugin) ValidateNonce(nonce string) bool {
	if nonce == "" {
		return false
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	t, exists := p.nonces[nonce]
	if !exists {
		return false
	}

	// Check if expired
	if time.Since(t) > NonceLifetime {
		delete(p.nonces, nonce)
		return false
	}

	// Consume the nonce
	delete(p.nonces, nonce)
	return true
}

// evictNoncesBatch evicts the oldest ~25% of server-provided nonces.
// Sorting is performed outside the lock to reduce contention.
func (p *Plugin) evictNoncesBatch() {
	const evictRatio = 4

	p.mu.Lock()
	snapshots := make([]entry, 0, len(p.nonces))
	for nonce, t := range p.nonces {
		snapshots = append(snapshots, entry{nonce, t})
	}
	p.mu.Unlock()

	target := len(snapshots) / evictRatio
	if target == 0 {
		return
	}
	slices.SortFunc(snapshots, func(a, b entry) int {
		if a.t.Before(b.t) {
			return -1
		}
		if a.t.After(b.t) {
			return 1
		}
		return 0
	})
	cutoff := snapshots[target-1].t

	toDelete := make(map[string]struct{}, target)
	for i := 0; i < target; i++ {
		if !snapshots[i].t.After(cutoff) {
			toDelete[snapshots[i].jti] = struct{}{}
		}
	}

	p.mu.Lock()
	for nonce := range toDelete {
		delete(p.nonces, nonce)
	}
	p.mu.Unlock()
}

// WriteNonceHeader writes the DPoP-Nonce header to the response.
func (p *Plugin) WriteNonceHeader(w http.ResponseWriter) {
	nonce := p.GenerateNonce()
	w.Header().Set(NonceHeader, nonce)
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

// escapeJSON escapes a string for safe inclusion in a JSON string value.
func escapeJSON(s string) string {
	s = strconv.Quote(s)
	// strconv.Quote wraps in double quotes; strip them for embedding.
	return strings.TrimPrefix(strings.TrimSuffix(s, "\""), "\"")
}
