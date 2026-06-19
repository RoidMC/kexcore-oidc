package storm

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter provides a simple in-memory token bucket rate limiter
// for production IAM deployments. It implements http.Handler middleware
// and can be applied to specific routes or the entire engine.
//
// For distributed deployments, replace with a Redis-backed limiter
// (e.g. go-redis/redis_rate) by implementing the MiddlewareProvider interface.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     int           // requests per window
	window   time.Duration // sliding window duration
	cleanup  time.Duration // how often to clean expired buckets
	stopOnce sync.Once
	stopCh   chan struct{}
}

type bucket struct {
	timestamps []time.Time
}

// NewRateLimiter creates a rate limiter that allows `rate` requests
// per `window` per client IP. Expired entries are cleaned up every `window`.
//
// Example:
//
//	limiter := storm.NewRateLimiter(100, time.Minute) // 100 req/min per IP
//	engine.Use(limiter.Middleware)
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		window:  window,
		cleanup: window,
		stopCh:  make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Allow checks if a request from the given key is allowed.
// Returns true if the request is within the rate limit.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{}
		rl.buckets[key] = b
	}

	// Remove expired timestamps
	valid := b.timestamps[:0]
	for _, ts := range b.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	b.timestamps = valid

	if len(b.timestamps) >= rl.rate {
		return false
	}

	b.timestamps = append(b.timestamps, now)
	return true
}

// Middleware returns an http.Handler middleware that rate-limits by client IP.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := clientIP(r)
		if !rl.Allow(key) {
			w.Header().Set("Retry-After", rl.window.String())
			http.Error(w, `{"error":"rate_limit_exceeded","error_description":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Stop terminates the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopCh)
	})
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-rl.window)
			for key, b := range rl.buckets {
				expired := true
				for _, ts := range b.timestamps {
					if ts.After(cutoff) {
						expired = false
						break
					}
				}
				if expired {
					delete(rl.buckets, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// clientIP extracts the client IP from the request, preferring
// X-Forwarded-For (for reverse proxy setups) then X-Real-IP,
// falling back to RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (client IP before proxy chain)
		for i, c := range xff {
			if c == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Strip port from RemoteAddr
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
