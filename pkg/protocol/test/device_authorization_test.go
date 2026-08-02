package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
)

func TestDeviceAuthorizationResponse_UnmarshalJSON(t *testing.T) {
	t.Run("verification_url fallback", func(t *testing.T) {
		jsonStr := `{
			"device_code": "dc_123",
			"user_code": "ABCD-EFGH",
			"verification_url": "https://example.com/verify",
			"expires_in": 300,
			"interval": 5
		}`

		var resp protocol.DeviceAuthorizationResponse
		require.NoError(t, json.Unmarshal([]byte(jsonStr), &resp))

		assert.Equal(t, "dc_123", resp.DeviceCode)
		assert.Equal(t, "ABCD-EFGH", resp.UserCode)
		assert.Equal(t, "https://example.com/verify", resp.VerificationURI)
		assert.Equal(t, 300, resp.ExpiresIn)
		assert.Equal(t, 5, resp.Interval)
	})

	t.Run("verification_uri preferred", func(t *testing.T) {
		jsonStr := `{
			"device_code": "dc_456",
			"user_code": "IJKL-MNOP",
			"verification_uri": "https://example.com/device",
			"verification_url": "https://example.com/fallback",
			"expires_in": 600
		}`

		var resp protocol.DeviceAuthorizationResponse
		require.NoError(t, json.Unmarshal([]byte(jsonStr), &resp))

		assert.Equal(t, "dc_456", resp.DeviceCode)
		assert.Equal(t, "IJKL-MNOP", resp.UserCode)
		assert.Equal(t, "https://example.com/device", resp.VerificationURI)
		assert.Equal(t, 600, resp.ExpiresIn)
		assert.Equal(t, 0, resp.Interval)
	})

	t.Run("verification_uri_complete optional", func(t *testing.T) {
		jsonStr := `{
			"device_code": "dc_789",
			"user_code": "QRST-UVWX",
			"verification_uri": "https://example.com/device",
			"verification_uri_complete": "https://example.com/device?user_code=QRST-UVWX",
			"expires_in": 900
		}`

		var resp protocol.DeviceAuthorizationResponse
		require.NoError(t, json.Unmarshal([]byte(jsonStr), &resp))

		assert.Equal(t, "https://example.com/device?user_code=QRST-UVWX", resp.VerificationURIComplete)
	})
}
