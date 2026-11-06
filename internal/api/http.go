package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

// httpError is a transport error serialized as an ErrorResponse.
type httpError struct {
	status  int
	message string
	details string
}

// decodeJSON validates Content-Type and body size, decodes one JSON value, and
// rejects trailing data. Unknown fields are ignored.
func (h *Handler) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) *httpError {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return &httpError{415, "unsupported media type", "Content-Type must be application/json"}
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, h.bodyLimit))
	if err := decoder.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return &httpError{413, "request body too large", err.Error()}
		}
		return &httpError{400, err.Error(), ""}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return &httpError{400, "trailing data", ""}
	}
	return nil
}

// writeJSON writes v as JSON with the given status code.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.log.Error("encode response", "error", err)
	}
}

// writeError writes e as an ErrorResponse.
func (h *Handler) writeError(w http.ResponseWriter, e *httpError) {
	h.writeJSON(w, e.status, map[string]any{
		"message": e.message,
		"details": e.details,
	})
}

// getHTTPError converts a validation error into an HTTP 400 response.
func getHTTPError(err error) *httpError {
	return &httpError{400, "invalid request", err.Error()}
}
