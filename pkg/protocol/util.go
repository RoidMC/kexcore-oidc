package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// mergeAndMarshalClaims merges registered and the custom
// claims map into a single JSON object.
// Registered fields overwrite custom claims.
func mergeAndMarshalClaims(registered any, extraClaims map[string]any) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := json.NewEncoder(buf).Encode(registered); err != nil {
		return nil, fmt.Errorf("protocol registered claims: %w", err)
	}

	if len(extraClaims) > 0 {
		merged := make(map[string]any)
		for k, v := range extraClaims {
			merged[k] = v
		}

		if err := json.NewDecoder(buf).Decode(&merged); err != nil {
			return nil, fmt.Errorf("protocol registered claims: %w", err)
		}

		if err := json.NewEncoder(buf).Encode(merged); err != nil {
			return nil, fmt.Errorf("protocol custom claims: %w", err)
		}
	}

	return buf.Bytes(), nil
}

// unmarshalJSONMulti unmarshals the same JSON data into multiple destinations.
// Each destination must be a pointer, as per json.Unmarshal rules.
func unmarshalJSONMulti(data []byte, destinations ...any) error {
	for _, dst := range destinations {
		if err := json.Unmarshal(data, dst); err != nil {
			return fmt.Errorf("protocol: %w into %T", err, dst)
		}
	}
	return nil
}
