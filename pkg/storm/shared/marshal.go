package shared

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
)

// MarshalJSON writes a JSON response with status 200.
func MarshalJSON(w http.ResponseWriter, i any) {
	MarshalJSONWithStatus(w, i, http.StatusOK)
}

// MarshalJSONWithStatus writes a JSON response with the given status code.
func MarshalJSONWithStatus(w http.ResponseWriter, i any, status int) {
	w.Header().Set("Content-Type", "application/json")
	if i == nil || (reflect.ValueOf(i).Kind() == reflect.Ptr && reflect.ValueOf(i).IsNil()) {
		w.WriteHeader(status)
		return
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(i); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	buf.WriteTo(w)
}

// ConcatenateJSON merges two JSON objects into one.
// Useful for combining ID token claims with custom claims.
func ConcatenateJSON(first, second []byte) ([]byte, error) {
	if !bytes.HasSuffix(first, []byte{'}'}) {
		return nil, fmt.Errorf("invalid JSON object: %s", first)
	}
	if !bytes.HasPrefix(second, []byte{'{'}) {
		return nil, fmt.Errorf("invalid JSON object: %s", second)
	}
	if len(first) == 2 {
		return second, nil
	}
	if len(second) == 2 {
		return first, nil
	}
	result := make([]byte, len(first)+len(second)-1)
	copy(result, first[:len(first)-1])
	result[len(first)-1] = ','
	copy(result[len(first):], second[1:])
	return result, nil
}
