// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel 
// Modifications Copyright 2026 RoidMC Studios

package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
)

func MarshalJSON(w http.ResponseWriter, i any) {
	MarshalJSONWithStatus(w, i, http.StatusOK)
}

func MarshalJSONWithStatus(w http.ResponseWriter, i any, status int) {
	w.Header().Set("content-type", "application/json")
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

func ConcatenateJSON(first, second []byte) ([]byte, error) {
	if !bytes.HasSuffix(first, []byte{'}'}) {
		return nil, fmt.Errorf("jws: invalid JSON %s", first)
	}
	if !bytes.HasPrefix(second, []byte{'{'}) {
		return nil, fmt.Errorf("jws: invalid JSON %s", second)
	}
	// check empty
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
