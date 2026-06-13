package client

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Sentinel errors returned by Client methods. Use errors.Is to check.
var (
	ErrNotFound  = errors.New("not found") // HTTP 404
	ErrForbidden = errors.New("forbidden") // HTTP 403
	ErrConflict  = errors.New("conflict")  // HTTP 409
)

// APIError is returned for non-2xx responses not covered by the named sentinels.
type APIError struct {
	Status int
	Detail string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Detail)
}

// mapError converts an HTTP status code and response body into a typed error.
// It attempts to decode the huma RFC 7807 ErrorModel for the detail message.
func mapError(status int, body []byte) error {
	detail := extractDetail(body)
	switch status {
	case 403:
		return ErrForbidden
	case 404:
		return ErrNotFound
	case 409:
		return ErrConflict
	default:
		return &APIError{Status: status, Detail: detail}
	}
}

func extractDetail(body []byte) string {
	var model ErrorModel
	if err := json.Unmarshal(body, &model); err == nil && model.Detail != nil {
		return *model.Detail
	}
	return string(body)
}
