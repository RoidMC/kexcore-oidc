package shared

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
)

// WriteError writes an OIDC error response to the response writer.
// It inspects the error chain for StatusError and oidc.Error to determine
// the correct HTTP status code and JSON body.
//
// This is a shared utility; plugins may choose to use it or implement
// their own error handling.
func WriteError(w http.ResponseWriter, r *http.Request, err error, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	statusCode := http.StatusBadRequest
	oidcErr := oidc.DefaultToServerError(err, err.Error())

	var se StatusError
	if errors.As(err, &se) {
		statusCode = se.statusCode
		oidcErr = oidc.DefaultToServerError(se.parent, se.parent.Error())
	}

	if oidcErr.ErrorType == oidc.ServerError {
		statusCode = http.StatusInternalServerError
	}

	logger.Log(r.Context(), oidcErr.LogLevel(), "request error",
		slog.Any("oidc_error", oidcErr),
		slog.Int("status_code", statusCode),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(oidcErr)
}

// StatusError wraps an error with an explicit HTTP status code.
// Plugins may return this to signal non-standard status codes.
type StatusError struct {
	parent     error
	statusCode int
}

// NewStatusError creates a StatusError.
func NewStatusError(parent error, statusCode int) StatusError {
	return StatusError{parent: parent, statusCode: statusCode}
}

// AsStatusError unwraps a StatusError from err, or creates a new one.
func AsStatusError(err error, statusCode int) StatusError {
	var se StatusError
	if errors.As(err, &se) {
		return se
	}
	return NewStatusError(err, statusCode)
}

func (e StatusError) Error() string {
	return e.parent.Error()
}

func (e StatusError) Unwrap() error {
	return e.parent
}
