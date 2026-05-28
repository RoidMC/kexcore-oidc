package protocol_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

func testdataPath(name string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	base := filepath.Dir(thisFile)
	return filepath.Join(base, "..", "kit", "data", "discovery", name)
}

func TestDiscoveryConfiguration_MarshalJSON(t *testing.T) {
	doc := &protocol.DiscoveryConfiguration{
		Issuer:                           "https://op.example.com",
		AuthorizationEndpoint:            "https://op.example.com/authorize",
		TokenEndpoint:                    "https://op.example.com/token",
		UserinfoEndpoint:                 "https://op.example.com/userinfo",
		JWKSURI:                          "https://op.example.com/jwks.json",
		ScopesSupported:                  []string{"openid", "profile"},
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ClaimsParameterSupported:         true,
		RequestURIParameterSupported:     true,
	}

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if result["issuer"] != "https://op.example.com" {
		t.Errorf("issuer = %v", result["issuer"])
	}
	if result["scopes_supported"] == nil {
		t.Error("scopes_supported missing")
	}
	if result["claims_parameter_supported"] != true {
		t.Error("claims_parameter_supported should be true")
	}
}

func TestDiscoveryConfiguration_MarshalJSON_Extra(t *testing.T) {
	doc := &protocol.DiscoveryConfiguration{
		Issuer:                           "https://op.example.com",
		AuthorizationEndpoint:            "https://op.example.com/authorize",
		TokenEndpoint:                    "https://op.example.com/token",
		JWKSURI:                          "https://op.example.com/jwks.json",
		ScopesSupported:                  []string{"openid"},
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		Extra: map[string]any{
			"custom_extension_field":    "extension-value",
			"my_plugin_specific_config": map[string]any{"enabled": true},
		},
	}

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if result["custom_extension_field"] != "extension-value" {
		t.Errorf("custom_extension_field = %v", result["custom_extension_field"])
	}
	if result["my_plugin_specific_config"] == nil {
		t.Error("my_plugin_specific_config missing")
	}
}

func TestDiscoveryConfiguration_MarshalJSON_NoExtra(t *testing.T) {
	doc := &protocol.DiscoveryConfiguration{
		Issuer: "https://op.example.com",
	}
	doc.Extra = nil

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	mustBeJSON(t, data)

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if result["issuer"] != "https://op.example.com" {
		t.Errorf("issuer = %v", result["issuer"])
	}
}

func TestDiscoveryConfiguration_UnmarshalJSON(t *testing.T) {
	data, err := os.ReadFile(testdataPath("oidc.endpoint.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var doc protocol.DiscoveryConfiguration
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if doc.Issuer != "https://op.example.com" {
		t.Errorf("issuer = %q", doc.Issuer)
	}
	if doc.AuthorizationEndpoint != "https://op.example.com/authorize" {
		t.Errorf("authorization_endpoint = %q", doc.AuthorizationEndpoint)
	}
	if doc.TokenEndpoint != "https://op.example.com/token" {
		t.Errorf("token_endpoint = %q", doc.TokenEndpoint)
	}

	scopes := doc.ScopesSupported
	if scopes == nil {
		t.Fatalf("scopes_supported type = %T", doc.ScopesSupported)
	}
	if len(scopes) == 0 {
		t.Error("scopes_supported is empty")
	}

	if !doc.BackChannelLogoutSupported {
		t.Error("backchannel_logout_supported should be true")
	}
	if !doc.TLSClientCertificateBoundAccessTokens {
		t.Error("tls_client_certificate_bound_access_tokens should be true")
	}
	if doc.FrontChannelLogoutSupported {
		t.Error("frontchannel_logout_supported should be false")
	}

	if doc.CheckSessionIframe != "https://op.example.com/check-session" {
		t.Errorf("check_session_iframe = %q", doc.CheckSessionIframe)
	}
	if doc.FrontChannelLogoutEndpoint != "https://op.example.com/frontchannel-logout" {
		t.Errorf("frontchannel_logout_endpoint = %q", doc.FrontChannelLogoutEndpoint)
	}
	if doc.RequirePushedAuthorizationRequests {
		t.Error("require_pushed_authorization_requests should be false")
	}
	if !doc.AuthorizationResponseISSParameterSupported {
		t.Error("authorization_response_iss_parameter_supported should be true")
	}
	if doc.IntrospectionEndpointAuthSigningAlgValuesSupported == nil {
		t.Error("introspection_endpoint_auth_signing_alg_values_supported missing")
	}
	if doc.RevocationEndpointAuthSigningAlgValuesSupported == nil {
		t.Error("revocation_endpoint_auth_signing_alg_values_supported missing")
	}
	if doc.RequestObjectEncryptionAlgValuesSupported == nil {
		t.Error("request_object_encryption_alg_values_supported missing")
	}
	if doc.RequestObjectEncryptionEncValuesSupported == nil {
		t.Error("request_object_encryption_enc_values_supported missing")
	}

	mtls, ok := doc.MTLSEndpointAliases.(map[string]any)
	if !ok {
		t.Fatalf("mtls_endpoint_aliases type = %T", doc.MTLSEndpointAliases)
	}
	if mtls["token_endpoint"] != "https://mtls.op.example.com/token" {
		t.Errorf("mtls token_endpoint = %v", mtls["token_endpoint"])
	}
}

func TestDiscoveryConfiguration_UnmarshalJSON_Extra(t *testing.T) {
	data, err := os.ReadFile(testdataPath("oidc.endpoint.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var doc protocol.DiscoveryConfiguration
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if doc.Extra == nil {
		t.Fatal("Extra is nil, should contain unknown fields")
	}
	if doc.Extra["custom_extension_field"] != "value-from-extension-rfc" {
		t.Errorf("Extra custom_extension_field = %v", doc.Extra["custom_extension_field"])
	}
	if doc.Extra["my_plugin_specific_config"] == nil {
		t.Error("Extra my_plugin_specific_config missing")
	}
	if doc.Extra["issuer"] != nil {
		t.Error("issuer should not be in Extra")
	}
	if doc.Extra["token_endpoint"] != nil {
		t.Error("token_endpoint should not be in Extra")
	}
}

func TestDiscoveryConfiguration_RoundTrip(t *testing.T) {
	data, err := os.ReadFile(testdataPath("oidc.endpoint.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var doc protocol.DiscoveryConfiguration
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	marshaled, err := json.Marshal(&doc)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var doc2 protocol.DiscoveryConfiguration
	if err := json.Unmarshal(marshaled, &doc2); err != nil {
		t.Fatalf("second UnmarshalJSON: %v", err)
	}

	if doc2.Issuer != doc.Issuer {
		t.Errorf("issuer mismatch: %q vs %q", doc2.Issuer, doc.Issuer)
	}
	if doc2.TLSClientCertificateBoundAccessTokens != doc.TLSClientCertificateBoundAccessTokens {
		t.Error("tls_client_certificate_bound_access_tokens mismatch")
	}
	if doc2.BackChannelLogoutSupported != doc.BackChannelLogoutSupported {
		t.Error("backchannel_logout_supported mismatch")
	}

	if doc2.CheckSessionIframe != doc.CheckSessionIframe {
		t.Error("check_session_iframe mismatch")
	}
	if doc2.FrontChannelLogoutEndpoint != doc.FrontChannelLogoutEndpoint {
		t.Error("frontchannel_logout_endpoint mismatch")
	}
	if doc2.RequirePushedAuthorizationRequests != doc.RequirePushedAuthorizationRequests {
		t.Error("require_pushed_authorization_requests mismatch")
	}
	if doc2.AuthorizationResponseISSParameterSupported != doc.AuthorizationResponseISSParameterSupported {
		t.Error("authorization_response_iss_parameter_supported mismatch")
	}

	if doc2.Extra["custom_extension_field"] != doc.Extra["custom_extension_field"] {
		t.Error("Extra custom_extension_field mismatch")
	}
	if doc2.Extra["my_plugin_specific_config"] == nil {
		t.Error("Extra my_plugin_specific_config missing after round-trip")
	}
}

func TestDiscoveryConfiguration_UnmarshalJSON_Minimal(t *testing.T) {
	minimal := []byte(`{
		"issuer": "https://minimal.op.example.com",
		"authorization_endpoint": "https://minimal.op.example.com/authorize",
		"token_endpoint": "https://minimal.op.example.com/token",
		"jwks_uri": "https://minimal.op.example.com/jwks.json",
		"response_types_supported": ["code"],
		"subject_types_supported": ["public"],
		"id_token_signing_alg_values_supported": ["RS256"]
	}`)

	var doc protocol.DiscoveryConfiguration
	if err := json.Unmarshal(minimal, &doc); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if doc.Issuer != "https://minimal.op.example.com" {
		t.Errorf("issuer = %q", doc.Issuer)
	}
	if doc.TLSClientCertificateBoundAccessTokens {
		t.Error("tls_client_certificate_bound_access_tokens should default to false")
	}
	if len(doc.Extra) > 0 {
		t.Errorf("Extra should be empty, got %v", doc.Extra)
	}
}

func TestDiscoveryConfiguration_FieldOrdering(t *testing.T) {
	doc := &protocol.DiscoveryConfiguration{
		Issuer:                           "https://op.example.com",
		AuthorizationEndpoint:            "https://op.example.com/authorize",
		TokenEndpoint:                    "https://op.example.com/token",
		JWKSURI:                          "https://op.example.com/jwks.json",
		ScopesSupported:                  []string{"openid"},
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	mustBeJSON(t, data)

	if len(data) == 0 || data[0] != '{' {
		t.Fatal("not a JSON object")
	}
	firstField := `"issuer"`
	pos := 0
	for i := range data {
		if i+len(firstField) <= len(data) && string(data[i:i+len(firstField)]) == firstField {
			pos = i
			break
		}
	}
	if pos > 20 {
		t.Errorf("issuer should appear early in output, found at byte %d", pos)
	}
}

func mustBeJSON(t *testing.T, data []byte) {
	t.Helper()
	if !json.Valid(data) {
		t.Fatalf("not valid JSON: %s", string(data))
	}
}

func TestDiscoveryConfiguration_ExtraSurvivesMarshalUnmarshal(t *testing.T) {
	doc := &protocol.DiscoveryConfiguration{
		Issuer:                           "https://op.example.com",
		AuthorizationEndpoint:            "https://op.example.com/authorize",
		TokenEndpoint:                    "https://op.example.com/token",
		JWKSURI:                          "https://op.example.com/jwks.json",
		ScopesSupported:                  []string{"openid"},
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		Extra: map[string]any{
			"custom_int":    42,
			"custom_float":  3.14,
			"custom_bool":   true,
			"custom_string": "hello",
			"custom_array":  []any{"a", "b", "c"},
		},
	}

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var doc2 protocol.DiscoveryConfiguration
	if err := json.Unmarshal(data, &doc2); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if doc2.Extra["custom_int"].(float64) != 42 {
		t.Errorf("custom_int = %v", doc2.Extra["custom_int"])
	}
	if doc2.Extra["custom_float"].(float64) != 3.14 {
		t.Errorf("custom_float = %v", doc2.Extra["custom_float"])
	}
	if doc2.Extra["custom_bool"] != true {
		t.Errorf("custom_bool = %v", doc2.Extra["custom_bool"])
	}
	if doc2.Extra["custom_string"] != "hello" {
		t.Errorf("custom_string = %v", doc2.Extra["custom_string"])
	}
	arr, ok := doc2.Extra["custom_array"].([]any)
	if !ok || len(arr) != 3 {
		t.Errorf("custom_array = %v", doc2.Extra["custom_array"])
	}
}
