package dpop

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
)

// --- tests ---

func TestNewWithConfig(t *testing.T) {
	p := NewWithConfig()
	if p.Name() != "dpop" {
		t.Errorf("Name() = %q, want %q", p.Name(), "dpop")
	}
	if p.Category() != storm.CategoryStandard {
		t.Errorf("Category() = %v, want %v", p.Category(), storm.CategoryStandard)
	}
	p.Stop()
}

func TestRequires(t *testing.T) {
	p := NewWithConfig()
	requires := p.Requires()
	if requires != nil {
		t.Errorf("Requires() = %v, want nil", requires)
	}
	p.Stop()
}

func TestGenerateNonce(t *testing.T) {
	p := NewWithConfig()
	defer p.Stop()

	nonce1 := p.GenerateNonce()
	nonce2 := p.GenerateNonce()

	if nonce1 == "" {
		t.Error("GenerateNonce returned empty string")
	}
	if nonce1 == nonce2 {
		t.Error("expected unique nonces")
	}
}

func TestValidateNonce_Valid(t *testing.T) {
	p := NewWithConfig()
	defer p.Stop()

	nonce := p.GenerateNonce()
	if !p.ValidateNonce(nonce) {
		t.Error("expected valid nonce")
	}
}

func TestValidateNonce_Consumed(t *testing.T) {
	p := NewWithConfig()
	defer p.Stop()

	nonce := p.GenerateNonce()
	if !p.ValidateNonce(nonce) {
		t.Error("expected valid nonce")
	}
	// Second validation should fail (nonce consumed)
	if p.ValidateNonce(nonce) {
		t.Error("expected nonce to be consumed after first validation")
	}
}

func TestValidateNonce_Invalid(t *testing.T) {
	p := NewWithConfig()
	defer p.Stop()

	if p.ValidateNonce("invalid-nonce") {
		t.Error("expected invalid nonce")
	}
}

func TestValidateNonce_Empty(t *testing.T) {
	p := NewWithConfig()
	defer p.Stop()

	if p.ValidateNonce("") {
		t.Error("expected empty nonce to be invalid")
	}
}

func TestWriteNonceHeader(t *testing.T) {
	p := NewWithConfig()
	defer p.Stop()

	w := httptest.NewRecorder()
	p.WriteNonceHeader(w)

	nonce := w.Header().Get(NonceHeader)
	if nonce == "" {
		t.Error("expected DPoP-Nonce header")
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	if DPoPFromContext(ctx) != nil {
		t.Error("expected nil proof from empty context")
	}

	proof := &Proof{
		JKT:      "test-jkt",
		HTM:      "POST",
		HTU:      "https://auth.example.com/token",
		IssuedAt: time.Now(),
		UniqueID: "test-jti",
	}

	ctx = ContextWithDPoP(ctx, proof)
	got := DPoPFromContext(ctx)
	if got == nil {
		t.Fatal("expected proof from context")
	}
	if got.JKT != "test-jkt" {
		t.Errorf("JKT = %q, want %q", got.JKT, "test-jkt")
	}
}

func TestMiddleware_NoDPoPHeader(t *testing.T) {
	p := NewWithConfig()
	defer p.Stop()

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof := DPoPFromContext(r.Context())
		if proof != nil {
			t.Error("expected no proof without DPoP header")
		}
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCleanupNonceCache(t *testing.T) {
	p := NewWithConfig()
	defer p.Stop()

	// Add a nonce
	p.GenerateNonce()

	// Manually set an expired nonce
	p.mu.Lock()
	p.nonces["expired"] = time.Now().Add(-NonceLifetime * 2)
	p.mu.Unlock()

	p.CleanupNonceCache()

	p.mu.Lock()
	_, exists := p.nonces["expired"]
	p.mu.Unlock()

	if exists {
		t.Error("expected expired nonce to be cleaned up")
	}
}

func TestConstants(t *testing.T) {
	if Header != "DPoP" {
		t.Errorf("Header = %q, want %q", Header, "DPoP")
	}
	if AccessTokenType != "DPoP" {
		t.Errorf("AccessTokenType = %q, want %q", AccessTokenType, "DPoP")
	}
	if NonceHeader != "DPoP-Nonce" {
		t.Errorf("NonceHeader = %q, want %q", NonceHeader, "DPoP-Nonce")
	}
	if MaxProofAge != 5*time.Minute {
		t.Errorf("MaxProofAge = %v, want %v", MaxProofAge, 5*time.Minute)
	}
	if NonceLifetime != 5*time.Minute {
		t.Errorf("NonceLifetime = %v, want %v", NonceLifetime, 5*time.Minute)
	}
}

func TestCNFClaim(t *testing.T) {
	claim := CNFClaim("test-jkt")
	jkt, ok := claim["jkt"].(string)
	if !ok {
		t.Fatal("cnf claim missing jkt")
	}
	if jkt != "test-jkt" {
		t.Errorf("jkt = %q, want %q", jkt, "test-jkt")
	}
}

func TestValidateBoundToken_Success(t *testing.T) {
	proof := &Proof{JKT: "test-jkt"}
	tokenCNF := map[string]any{"jkt": "test-jkt"}

	err := ValidateBoundToken(tokenCNF, proof)
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}
}

func TestValidateBoundToken_Mismatch(t *testing.T) {
	proof := &Proof{JKT: "test-jkt"}
	tokenCNF := map[string]any{"jkt": "other-jkt"}

	err := ValidateBoundToken(tokenCNF, proof)
	if err == nil {
		t.Error("expected error for mismatched JKT")
	}
}

func TestValidateBoundToken_NilProof(t *testing.T) {
	tokenCNF := map[string]any{"jkt": "test-jkt"}

	err := ValidateBoundToken(tokenCNF, nil)
	if err == nil {
		t.Error("expected error for nil proof")
	}
}

func TestValidateBoundToken_MissingCNF(t *testing.T) {
	proof := &Proof{JKT: "test-jkt"}
	tokenCNF := map[string]any{}

	err := ValidateBoundToken(tokenCNF, proof)
	if err == nil {
		t.Error("expected error for missing cnf.jkt")
	}
}
