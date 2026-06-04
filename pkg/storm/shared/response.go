package shared

import (
	"net/http"

	httputil "github.com/roidmc/kexcore-oidc/pkg/util/http"
)

// SetUserInfoHeaders sets the headers required by OIDC Core §5.3.2 and RFC 6750.
func SetUserInfoHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// JSONResponse writes a JSON response with the given status code.
// If data is nil, only the status code is written.
// Delegates to util/http.MarshalJSONWithStatus for the actual encoding.
func JSONResponse(w http.ResponseWriter, data any, statusCode int) {
	httputil.MarshalJSONWithStatus(w, data, statusCode)
}

// RedirectResponse sends a 302 Found redirect.
func RedirectResponse(w http.ResponseWriter, r *http.Request, url string) {
	http.Redirect(w, r, url, http.StatusFound)
}

// NoContentResponse sends a 204 No Content response.
func NoContentResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}
