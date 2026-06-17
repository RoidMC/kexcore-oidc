package protocol

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

const DiscoveryEndpoint = "/.well-known/openid-configuration"

// KnownDiscoveryKeys contains all JSON field names from DiscoveryConfiguration struct tags.
// This is auto-generated via reflection and can be used to filter discovery fields.
var KnownDiscoveryKeys map[string]bool

func init() {
	KnownDiscoveryKeys = make(map[string]bool)
	t := reflect.TypeOf(DiscoveryConfiguration{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		KnownDiscoveryKeys[name] = true
	}
}

// DiscoveryConfiguration is the canonical OpenID Provider metadata structure.
// Fields are ordered per OIDC Discovery 1.0 §3. The struct IS the spec;
// field sequence maps to JSON ordering, json tags map to IANA-registered metadata names.
type DiscoveryConfiguration struct {
	// REQUIRED. issuer is the URL of the OP, used as iss claim in tokens.
	// OIDC Discovery 1.0 §3.1
	Issuer string `json:"issuer"`

	// REQUIRED. Authorization Endpoint URL (OAuth 2.0 Authorization Endpoint).
	// Used for all interactive login flows.
	// OIDC Discovery 1.0 §3.2
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`

	// REQUIRED. Token Endpoint URL (OAuth 2.0 Token Endpoint).
	// Used by all grant types to obtain tokens.
	// OIDC Discovery 1.0 §3.3
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// RECOMMENDED. UserInfo Endpoint URL.
	// Returns claims about the authenticated End-User.
	// OIDC Core 1.0 §5.3 / OIDC Discovery 1.0 §3.4
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	// REQUIRED. JWKS URI containing the OP's public keys for token signature verification.
	// OIDC Discovery 1.0 §3.5 / OIDC Core 1.0 §7.3
	JWKSURI string `json:"jwks_uri,omitempty"`

	// RECOMMENDED. Dynamic Client Registration Endpoint (RFC 7591).
	// OIDC Discovery 1.0 §3.6
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// End Session Endpoint URL for RP-Initiated Logout.
	// OIDC Session Management §5 / OIDC RP-Initiated Logout §2
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`

	// Check Session iframe URL for OP-initiated session state monitoring.
	// OIDC Session Management §4
	CheckSessionIframe string `json:"check_session_iframe,omitempty"`

	// Back-Channel Logout Endpoint URI to receive logout tokens.
	// OIDC Back-Channel Logout §2.5
	BackChannelLogoutEndpoint string `json:"backchannel_logout_endpoint,omitempty"`

	// OPTIONAL. Whether the OP supports session IDs in back-channel logout tokens.
	// OIDC Back-Channel Logout §2.5
	BackChannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"`

	// OPTIONAL. Whether the OP supports back-channel logout.
	// OIDC Back-Channel Logout §2.5
	BackChannelLogoutSupported bool `json:"backchannel_logout_supported,omitempty"`

	// Front-Channel Logout Endpoint URL via user-agent redirect.
	// OIDC Front-Channel Logout §3
	FrontChannelLogoutEndpoint string `json:"frontchannel_logout_endpoint,omitempty"`

	// OPTIONAL. Whether the OP supports session IDs in front-channel logout.
	// OIDC Front-Channel Logout §3
	FrontChannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported,omitempty"`

	// OPTIONAL. Whether the OP supports front-channel logout.
	// OIDC Front-Channel Logout §3
	FrontChannelLogoutSupported bool `json:"frontchannel_logout_supported,omitempty"`

	// Token Exchange Endpoint URL for cross-domain and delegation token exchange.
	// RFC 8693 §4 (OAuth 2.0 Token Exchange)
	TokenExchangeEndpoint string `json:"token_exchange_endpoint,omitempty"`

	// Device Authorization Endpoint URL for browserless and input-constrained devices.
	// RFC 8628 §4 (OAuth 2.0 Device Authorization Grant)
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

	// Backchannel Authentication Endpoint URL for Client-Initiated Backchannel Authentication.
	// CIBA Core 1.0 §4 (OpenID Connect Client-Initiated Backchannel Authentication)
	BackchannelAuthenticationEndpoint string `json:"backchannel_authentication_endpoint,omitempty"`

	// Pushed Authorization Request Endpoint URL.
	// RFC 9126 §4 (OAuth 2.0 Pushed Authorization Requests)
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`

	// OPTIONAL. Whether PAR is required before authorization requests.
	// RFC 9126 §4
	RequirePushedAuthorizationRequests bool `json:"require_pushed_authorization_requests,omitempty"`

	// Token Introspection Endpoint URL for metadata about access/refresh tokens.
	// RFC 7662 §2 (OAuth 2.0 Token Introspection)
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// Token Revocation Endpoint URL for revoking access/refresh tokens.
	// RFC 7009 §2 (OAuth 2.0 Token Revocation)
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// RECOMMENDED. List of supported scope values (openid, profile, email, etc.).
	// OIDC Discovery 1.0 §3.7
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// REQUIRED. List of supported response_type values (code, id_token, etc.).
	// OIDC Discovery 1.0 §3.8
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`

	// OPTIONAL. List of supported response_mode values (query, fragment, form_post).
	// OIDC Discovery 1.0 §3.9
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// OPTIONAL. List of supported grant_type values.
	// OIDC Discovery 1.0 §3.10
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// OPTIONAL. List of supported ACR (Authentication Context Class Reference) values.
	// OIDC Discovery 1.0 §3.11
	ACRValuesSupported []string `json:"acr_values_supported,omitempty"`

	// REQUIRED. List of supported subject identifier types (public, pairwise).
	// OIDC Discovery 1.0 §3.12
	SubjectTypesSupported []string `json:"subject_types_supported,omitempty"`

	// REQUIRED. List of supported JWS algorithms for ID Token signing.
	// OIDC Discovery 1.0 §3.13
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`

	// OPTIONAL. List of supported JWE algorithms for ID Token encryption.
	// OIDC Discovery 1.0 §3.14
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`

	// OPTIONAL. List of supported JWE content encryption algorithms for ID Token.
	// OIDC Discovery 1.0 §3.15
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	// OPTIONAL. List of supported JWS algorithms for UserInfo JWT signing.
	// OIDC Discovery 1.0 §3.16
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`

	// OPTIONAL. List of supported JWE algorithms for UserInfo JWT encryption.
	// OIDC Discovery 1.0 §3.17
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`

	// OPTIONAL. List of supported JWE content encryption algorithms for UserInfo JWT.
	// OIDC Discovery 1.0 §3.18
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// OPTIONAL. List of supported JWS algorithms for Request Object signing.
	// OIDC Discovery 1.0 §3.19
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// OPTIONAL. List of supported JWE algorithms for Request Object encryption.
	// OIDC Discovery 1.0 §3.20
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`

	// OPTIONAL. List of supported JWE content encryption algorithms for Request Object.
	// OIDC Discovery 1.0 §3.21
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	// OPTIONAL. List of supported client authentication methods at the Token Endpoint.
	// Includes client_secret_post, private_key_jwt, tls_client_auth, etc.
	// OIDC Discovery 1.0 §3.22
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL. List of supported JWS algorithms for Token Endpoint authentication.
	// OIDC Discovery 1.0 §3.23
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// OPTIONAL. List of supported client authentication methods at the Introspection Endpoint.
	// RFC 8414 §2 (OAuth 2.0 Authorization Server Metadata)
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL. List of supported JWS algorithms for Introspection Endpoint authentication.
	// RFC 8414 §2 (OAuth 2.0 Authorization Server Metadata)
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`

	// OPTIONAL. List of supported client authentication methods at the Revocation Endpoint.
	// RFC 8414 §2 (OAuth 2.0 Authorization Server Metadata)
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL. List of supported JWS algorithms for Revocation Endpoint authentication.
	// RFC 8414 §2 (OAuth 2.0 Authorization Server Metadata)
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`

	// OPTIONAL. List of supported display parameter values (page, popup, touch, wap).
	// OIDC Discovery 1.0 §3.24
	DisplayValuesSupported []string `json:"display_values_supported,omitempty"`

	// OPTIONAL. List of supported claim types (normal, aggregated, distributed).
	// OIDC Discovery 1.0 §3.25
	ClaimTypesSupported []string `json:"claim_types_supported,omitempty"`

	// RECOMMENDED. List of claim names the OP supports for the UserInfo Endpoint.
	// OIDC Discovery 1.0 §3.26
	ClaimsSupported []string `json:"claims_supported,omitempty"`

	// OPTIONAL. Whether the claims request parameter is supported.
	// OIDC Discovery 1.0 §3.27
	ClaimsParameterSupported bool `json:"claims_parameter_supported,omitempty"`

	// OPTIONAL. List of locale codes for claims content.
	// OIDC Discovery 1.0 §3.28
	ClaimsLocalesSupported []string `json:"claims_locales_supported,omitempty"`

	// OPTIONAL. List of locale codes for UI content.
	// OIDC Discovery 1.0 §3.29
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"`

	// OPTIONAL. Whether the request request parameter is supported.
	// OIDC Discovery 1.0 §3.30
	RequestParameterSupported bool `json:"request_parameter_supported,omitempty"`

	// OPTIONAL. Whether the request_uri request parameter is supported.
	// OIDC Discovery 1.0 §3.31
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported,omitempty"`

	// OPTIONAL. Whether request_uri values must be pre-registered (Dynamic Client Registration).
	// OIDC Discovery 1.0 §3.32
	RequireRequestURIRegistration bool `json:"require_request_uri_registration,omitempty"`

	// OPTIONAL. List of supported PKCE code challenge methods (S256, plain).
	// RFC 7636 §4 (Proof Key for Code Exchange)
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	// OPTIONAL. Whether the OP returns iss in authorization response parameters.
	// RFC 8414 §2 (OAuth 2.0 Authorization Server Metadata)
	AuthorizationResponseISSParameterSupported bool `json:"authorization_response_iss_parameter_supported,omitempty"`

	// OPTIONAL. URL of the OP's service documentation for developers.
	// OIDC Discovery 1.0 §3.33
	ServiceDocumentation string `json:"service_documentation,omitempty"`

	// OPTIONAL. URL of the OP's privacy policy.
	// OIDC Discovery 1.0 §3.34
	OPPolicyURI string `json:"op_policy_uri,omitempty"`

	// OPTIONAL. URL of the OP's terms of service.
	// OIDC Discovery 1.0 §3.35
	OPTermsOfServiceURI string `json:"op_tos_uri,omitempty"`

	// OPTIONAL. List of supported JWE key management algorithms.
	// RFC 7516 §4 (JSON Web Encryption)
	JWEAlgValuesSupported []string `json:"jwe_alg_values_supported,omitempty"`

	// OPTIONAL. List of supported JWE content encryption algorithms.
	// RFC 7516 §4 (JSON Web Encryption)
	JWEEncValuesSupported []string `json:"jwe_enc_values_supported,omitempty"`

	// OPTIONAL. Whether the OP supports mutual-TLS client certificate-bound access tokens.
	// RFC 8705 §3.3 (OAuth 2.0 Mutual TLS)
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// OPTIONAL. Alternative mTLS-secured endpoint URLs for clients using mutual TLS.
	// RFC 8705 §5 (OAuth 2.0 Mutual TLS)
	MTLSEndpointAliases any `json:"mtls_endpoint_aliases,omitempty"`

	// OPTIONAL. Whether the OP supports Resource Indicators.
	// RFC 8707 §5 (Resource Indicators for OAuth 2.0)
	ResourceIndicatorsSupported bool `json:"resource_indicators_supported,omitempty"`

	// OPTIONAL. List of supported authorization_details type values.
	// RFC 9396 §6 (Rich Authorization Requests)
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`

	// OPTIONAL. List of supported CIBA token delivery modes.
	// CIBA Core 1.0 §4 (Client-Initiated Backchannel Authentication)
	BackchannelTokenDeliveryModesSupported []string `json:"backchannel_token_delivery_modes_supported,omitempty"`

	// OPTIONAL. List of JWS signing algorithms supported for CIBA signed authentication requests.
	// CIBA Core 1.0 §4
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`

	// OPTIONAL. List of JWS signing algorithms supported for JARM authorization responses.
	// JWT Secured Authorization Response Mode (JARM) §4
	AuthorizationSigningAlgValuesSupported []string `json:"authorization_signing_alg_values_supported,omitempty"`

	// Extra holds additional discovery fields contributed by plugins that
	// are not part of the standard metadata registry.
	Extra map[string]any `json:"-"`
}

func (d *DiscoveryConfiguration) MarshalJSON() ([]byte, error) {
	type disc DiscoveryConfiguration
	base, err := json.Marshal((*disc)(d))
	if err != nil {
		return nil, err
	}
	if len(d.Extra) == 0 {
		return base, nil
	}
	extra, err := json.Marshal(d.Extra)
	if err != nil {
		return nil, err
	}
	if len(base) <= 2 {
		return extra, nil
	}
	// base looks like  {"issuer":...}
	// extra looks like {"custom":...}
	// merge them by removing base's trailing } and extra's leading {
	if len(base) == 0 || base[len(base)-1] != '}' {
		return base, fmt.Errorf("protocol: unexpected base JSON tail")
	}
	if len(extra) == 0 || extra[0] != '{' {
		return base, fmt.Errorf("protocol: unexpected Extra JSON head")
	}
	maxInt := int(^uint(0) >> 1)
	extraTailLen := len(extra) - 1 // safe: len(extra) > 0 checked above
	if extraTailLen > maxInt-len(base) {
		return nil, fmt.Errorf("protocol: merged discovery JSON too large")
	}
	mergedCap := len(base) + extraTailLen
	merged := make([]byte, 0, mergedCap)
	merged = append(merged, base[:len(base)-1]...)
	merged = append(merged, ',')
	merged = append(merged, extra[1:]...)
	return merged, nil
}

func (d *DiscoveryConfiguration) UnmarshalJSON(data []byte) error {
	type disc DiscoveryConfiguration
	if err := json.Unmarshal(data, (*disc)(d)); err != nil {
		return err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	d.Extra = make(map[string]any)
	for k, v := range raw {
		if KnownDiscoveryKeys[k] {
			continue
		}
		var val any
		if err := json.Unmarshal(v, &val); err != nil {
			return err
		}
		d.Extra[k] = val
	}

	return nil
}
