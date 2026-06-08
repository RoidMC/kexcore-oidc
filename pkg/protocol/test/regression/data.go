// Package regression provides JSON serialization stability tests
// for OIDC protocol types.
//
// These tests ensure that changes to struct fields or tags
// do not accidentally break the JSON output format.
//
// Baseline data is stored in:
// pkg/protocol/kit/data/regression_data/
//
// **Design Principle**: JSON files are the Single Source of Truth.
// Tests read JSON → unmarshal → marshal → compare for stability.
package regression

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

const (
	RegressionAccessTokenClaims         = "protocol.AccessTokenClaims.json"
	RegressionIDTokenClaims             = "protocol.IDTokenClaims.json"
	RegressionUserInfo                  = "protocol.UserInfo.json"
	RegressionJWTProfileAssertionClaims = "protocol.JWTProfileAssertionClaims.json"
	RegressionIntrospectionResponse     = "protocol.IntrospectionResponse.json"
)

func regressionDataDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	base := filepath.Dir(thisFile)
	return filepath.Join(base, "..", "..", "kit", "data", "regression_data")
}

var AllRegressionFiles = []string{
	RegressionAccessTokenClaims,
	RegressionIDTokenClaims,
	RegressionUserInfo,
	RegressionJWTProfileAssertionClaims,
	RegressionIntrospectionResponse,
}

func LoadJSONData(filename string) ([]byte, error) {
	return os.ReadFile(filepath.Join(regressionDataDir(), filename))
}

func UnmarshalJSONData(filename string, target any) error {
	data, err := LoadJSONData(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
