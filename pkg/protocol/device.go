package protocol

import "encoding/json"

// DeviceAuthorizationRequest implements
// RFC 8628 §3.1 Device Authorization Request.
type DeviceAuthorizationRequest struct {
	Scopes   SpaceDelimitedArray `schema:"scope"`
	ClientID string              `schema:"client_id"`
}

// DeviceAuthorizationResponse implements
// RFC 8628 §3.2 Device Authorization Response.
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

func (resp *DeviceAuthorizationResponse) UnmarshalJSON(data []byte) error {
	type Alias DeviceAuthorizationResponse
	aux := &struct {
		VerificationURL string `json:"verification_url"`
		*Alias
	}{
		Alias: (*Alias)(resp),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if resp.VerificationURI == "" {
		resp.VerificationURI = aux.VerificationURL
	}
	return nil
}

// DeviceAccessTokenRequest implements
// RFC 8628 §3.4 Device Access Token Request.
type DeviceAccessTokenRequest struct {
	GrantType  GrantType `json:"grant_type" schema:"grant_type"`
	DeviceCode string    `json:"device_code" schema:"device_code"`
}
