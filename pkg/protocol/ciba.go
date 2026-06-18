package protocol

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// BackchannelAuthRequest represents the request parameters for the
// Backchannel Authentication Endpoint (POST /bc-authorize).
//
// OpenID Connect Client-Initiated Backchannel Authentication Core 1.0 §7
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-7
type BackchannelAuthRequest struct {
	Scope                   string   `json:"scope"                schema:"scope"`
	ClientNotificationToken string   `json:"client_notification_token,omitempty" schema:"client_notification_token"`
	LoginHintToken          string   `json:"login_hint_token,omitempty"       schema:"login_hint_token"`
	IDTokenHint             string   `json:"id_token_hint,omitempty"          schema:"id_token_hint"`
	LoginHint               string   `json:"login_hint,omitempty"             schema:"login_hint"`
	BindingMessage          string   `json:"binding_message,omitempty"        schema:"binding_message"`
	UserCode                string   `json:"user_code,omitempty"              schema:"user_code"`
	RequestedExpiry         FlexInt  `json:"requested_expiry,omitempty"       schema:"requested_expiry"`
	AcrValues               string   `json:"acr_values,omitempty"             schema:"acr_values"`
	Claims                  string   `json:"claims,omitempty"                 schema:"claims"`
	Resources               Audience `json:"resource,omitempty"               schema:"resource"`
}

// CIBARequestObject represents a signed CIBA authentication request (CIBA Core 1.0 §4).
// It embeds the standard JWT claims and the CIBA-specific request parameters.
type CIBARequestObject struct {
	Issuer    string   `json:"iss"`
	Audience  Audience `json:"aud"`
	ExpiresAt int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	JTI       string   `json:"jti,omitempty"`
	BackchannelAuthRequest
}

func (r *CIBARequestObject) GetIssuer() string {
	return r.Issuer
}

func (*CIBARequestObject) SetSignatureAlgorithm(algorithm string) {}

// BackchannelAuthResponse represents the response from the
// Backchannel Authentication Endpoint (POST /bc-authorize).
//
// CIBA Core 1.0 §7.1.2
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-7.1.2
type BackchannelAuthResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval,omitempty"`
}

// BackchannelTokenRequest extends AccessTokenRequest with CIBA-specific fields.
//
// CIBA Core 1.0 §8.1
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-8.1
type BackchannelTokenRequest struct {
	GrantType           string `json:"grant_type"            schema:"grant_type"`
	AuthReqID           string `json:"auth_req_id"           schema:"auth_req_id"`
	ClientAssertionType string `json:"client_assertion_type" schema:"client_assertion_type"`
	ClientAssertion     string `json:"client_assertion"      schema:"client_assertion"`
}

// CIBADeliveryMode defines how the CIBA response is delivered to the client.
//
// CIBA Core 1.0 §5
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-5
type CIBADeliveryMode string

const (
	// CIBAModePing: OP notifies the client via an HTTP POST to its
	// client_notification_endpoint when the authentication is complete.
	CIBAModePing CIBADeliveryMode = "ping"

	// CIBAModePoll: client polls the token endpoint to check completion.
	// This is the default if the client does not provide a notification endpoint.
	CIBAModePoll CIBADeliveryMode = "poll"
)

// FlexInt is an int that can be unmarshalled from both JSON string and number.
// CIBA Core 1.0 §7.1.1: requested_expiry may be sent as either a JSON string
// or a JSON number; the OP must accept either type.
type FlexInt int

func (fi *FlexInt) UnmarshalJSON(data []byte) error {
	// Try number first
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*fi = FlexInt(n)
		return nil
	}
	// Try string
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		*fi = FlexInt(n)
		return nil
	}
	return fmt.Errorf("cannot unmarshal %s into FlexInt", string(data))
}

// CIBAStatus represents the status of a CIBA authentication request.
type CIBAStatus string

const (
	CIBAStatusPending  CIBAStatus = "pending"
	CIBAStatusApproved CIBAStatus = "approved"
	CIBAStatusDenied   CIBAStatus = "denied"
	CIBAStatusConsumed CIBAStatus = "consumed" // Token already issued; auth_req_id cannot be reused.
)

// CIBAAuthRequestInfo contains information about a pending CIBA request
// to display on the approval page.
type CIBAAuthRequestInfo struct {
	AuthReqID      string    `json:"auth_req_id"`
	ClientID       string    `json:"client_id"`
	Scope          string    `json:"scope"`
	BindingMessage string    `json:"binding_message,omitempty"`
	UserCode       string    `json:"user_code,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// CIBAPollResponse is returned when the token endpoint receives a poll request
// but the authentication is not yet complete.
//
// CIBA Core 1.0 §8.2
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-8.2
type CIBAPollResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// NewBackchannelAuthResponse creates a new BackchannelAuthResponse with the given parameters.
func NewBackchannelAuthResponse(authReqID string, expiresIn int, interval int) *BackchannelAuthResponse {
	return &BackchannelAuthResponse{
		AuthReqID: authReqID,
		ExpiresIn: expiresIn,
		Interval:  interval,
	}
}
