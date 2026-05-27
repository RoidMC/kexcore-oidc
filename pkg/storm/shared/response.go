package shared

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// JSONResponse writes a JSON response with the given status code.
// If data is nil, only the status code is written.
func JSONResponse(w http.ResponseWriter, data any, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if data == nil {
		return
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	buf.WriteTo(w)
}

// RedirectResponse sends a 302 Found redirect.
func RedirectResponse(w http.ResponseWriter, r *http.Request, url string) {
	http.Redirect(w, r, url, http.StatusFound)
}

// NoContentResponse sends a 204 No Content response.
func NoContentResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}