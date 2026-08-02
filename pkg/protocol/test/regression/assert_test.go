//go:build !create_regression_data

package regression

import (
	"encoding/json"
	"testing"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
)

func TestJSONSerializationStability(t *testing.T) {
	for _, filename := range AllRegressionFiles {
		t.Run(filename, func(t *testing.T) {
			baselineData, err := LoadJSONData(filename)
			require.NoError(t, err, "failed to load baseline JSON file: %s", filename)

			var baselineMap map[string]any
			require.NoError(t, json.Unmarshal(baselineData, &baselineMap))

			remarshaledData, err := json.MarshalIndent(baselineMap, "", "\t")
			require.NoError(t, err)

			assert.JSONEq(t, string(baselineData), string(remarshaledData),
				"JSON structure changed after round-trip. If intentional, update baseline file.")

			testTypeSpecificRoundTrip(t, filename, baselineData)
		})
	}
}

func testTypeSpecificRoundTrip(t *testing.T, filename string, data []byte) {
	t.Helper()

	switch filename {
	case RegressionAccessTokenClaims:
		var claims protocol.AccessTokenClaims
		require.NoError(t, json.Unmarshal(data, &claims))
		remarshaled, err := json.Marshal(&claims)
		require.NoError(t, err)
		assert.JSONEq(t, string(data), string(remarshaled))

	case RegressionIDTokenClaims:
		var claims protocol.IDTokenClaims
		require.NoError(t, json.Unmarshal(data, &claims))
		remarshaled, err := json.Marshal(&claims)
		require.NoError(t, err)
		assert.JSONEq(t, string(data), string(remarshaled))

	case RegressionUserInfo:
		var info protocol.UserInfo
		require.NoError(t, json.Unmarshal(data, &info))
		remarshaled, err := json.Marshal(&info)
		require.NoError(t, err)
		assert.JSONEq(t, string(data), string(remarshaled))

	case RegressionJWTProfileAssertionClaims:
		var claims protocol.JWTProfileAssertionClaims
		require.NoError(t, json.Unmarshal(data, &claims))
		remarshaled, err := json.Marshal(&claims)
		require.NoError(t, err)
		assert.JSONEq(t, string(data), string(remarshaled))
	}
}

func TestJSONFieldOrder(t *testing.T) {
	for _, filename := range AllRegressionFiles {
		t.Run(filename, func(t *testing.T) {
			data, err := LoadJSONData(filename)
			require.NoError(t, err)

			output := string(data)

			if filename == RegressionIDTokenClaims || filename == RegressionAccessTokenClaims {
				issIndex := indexOf(output, `"iss"`)
				subIndex := indexOf(output, `"sub"`)

				assert.GreaterOrEqual(t, issIndex, 0, "issuer field should exist")
				assert.GreaterOrEqual(t, subIndex, 0, "subject field should exist")

				if issIndex >= 0 {
					assert.Less(t, issIndex, 500, "issuer should appear early in output")
				}
			}

			if filename == RegressionIntrospectionResponse {
				activeIndex := indexOf(output, `"active"`)
				assert.GreaterOrEqual(t, activeIndex, 0, "active field should exist")
				assert.Less(t, activeIndex, 200, "active should appear early in introspection response")
			}
		})
	}
}

// indexOf returns the index of substr in s, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
