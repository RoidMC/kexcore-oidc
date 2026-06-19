package par

import (
	"net/http"
	"sort"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
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

// truncate returns the first n characters of s, with "..." appended if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// formKeys returns a sorted list of form keys for debug logging.
func formKeys(form map[string][]string) []string {
	keys := make([]string, 0, len(form))
	for k := range form {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
