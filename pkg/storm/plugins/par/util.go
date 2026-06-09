package par

import (
	"net/http"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

// validatePARRequest validates the incoming PAR request.
func validatePARRequest(r *http.Request) (clientID, clientSecret string, err error) {
	clientID = r.Form.Get("client_id")
	clientSecret = r.Form.Get("client_secret")
	if clientID == "" {
		return "", "", protocol.ErrInvalidRequest().WithDescription("client_id is required")
	}
	return clientID, clientSecret, nil
}
