package shared

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
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
	oidcErr := protocol.DefaultToServerError(err, err.Error())

	var se StatusError
	if errors.As(err, &se) {
		statusCode = se.statusCode
		oidcErr = protocol.DefaultToServerError(se.parent, se.parent.Error())
	}

	if oidcErr.ErrorType == protocol.ServerError {
		statusCode = http.StatusInternalServerError
	}

	// RFC 6749 error type → HTTP status code mapping.
	// The error itself carries its preferred status code (set by the
	// protocol constructor). StatusError still takes precedence.
	if oidcErr.HTTPStatusCode() > 0 {
		statusCode = oidcErr.HTTPStatusCode()
	}

	logger.Log(r.Context(), oidcErr.LogLevel(), "request error",
		slog.Any("oidc_error", oidcErr),
		slog.Int("status_code", statusCode),
	)

	// Set WWW-Authenticate header for 401 responses (RFC 6750 §3)
	if statusCode == http.StatusUnauthorized {
		realm := ""
		if r != nil && r.Context() != nil {
			if issuer := protocol.IssuerFromContext(r.Context()); issuer != "" {
				realm = issuer
			}
		}
		if realm != "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`", error="invalid_token"`)
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
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
