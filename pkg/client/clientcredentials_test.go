package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/roidmc/kexcore-oidc/v3/pkg/protocol"
)

// TestClientCredentialsRequestShape guards against regressions where the
// client_credentials grant was sent as a refresh_token request and the
// client assertion was dropped from the token request.
func TestClientCredentialsRequestShape(t *testing.T) {
	var gotForm url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
		})
	}))
	defer ts.Close()

	req := &protocol.ClientCredentialsRequest{
		GrantType:           protocol.GrantTypeClientCredentials,
		ClientID:            "cid",
		ClientAssertion:     "assertion-jwt",
		ClientAssertionType: protocol.ClientAssertionTypeJWTAssertion,
	}

	if _, err := ClientCredentials(context.Background(), ts.URL, req, ts.Client()); err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}

	if got := gotForm.Get("grant_type"); got != "client_credentials" {
		t.Errorf("grant_type = %q, want client_credentials", got)
	}
	if got := gotForm.Get("client_assertion"); got != req.ClientAssertion {
		t.Errorf("client_assertion = %q, want %q", got, req.ClientAssertion)
	}
	if got := gotForm.Get("client_assertion_type"); got != req.ClientAssertionType {
		t.Errorf("client_assertion_type = %q, want %q", got, req.ClientAssertionType)
	}
}
