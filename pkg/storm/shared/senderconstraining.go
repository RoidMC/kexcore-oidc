package shared

import (
	"net/http"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// ValidateSenderConstraining verifies that the client's sender-constraining
// requirements are met for the incoming token endpoint request.
//
// Per-client configuration takes precedence over global flags. When both DPoP
// and mTLS are required, the client supports sender-constraining via either
// mechanism and at least one proof-of-possession MUST be presented (this is
// the common FAPI 2.0 case where the actual mechanism is chosen by the
// conformance variant / client request).
func ValidateSenderConstraining(client interface{}, globalDPoP, globalMtls bool, r *http.Request) error {
	requireDPoP := globalDPoP
	requireMtls := globalMtls
	if sc, ok := client.(SenderConstrainingProvider); ok {
		requireDPoP = sc.RequireDPoP()
		requireMtls = sc.RequireMtls()
	}

	hasDPoP := r.Header.Get("DPoP") != ""
	hasMtls := ClientCertFromContext(r.Context()) != nil

	// Both mechanisms enabled -> require at least one proof-of-possession.
	if requireDPoP && requireMtls {
		if !hasDPoP && !hasMtls {
			return protocol.ErrInvalidRequest().WithDescription("holder-of-key proof required (FAPI 2.0 sender-constrained tokens)")
		}
		return nil
	}
	if requireDPoP && !hasDPoP {
		return protocol.ErrInvalidRequest().WithDescription("DPoP proof required (FAPI 2.0 sender-constrained tokens)")
	}
	if requireMtls && !hasMtls {
		return protocol.ErrInvalidRequest().WithDescription("mTLS client certificate required (FAPI 2.0 sender-constrained tokens)")
	}
	return nil
}
