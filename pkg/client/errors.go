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
	// sentinel is the named error this status maps to, if any, so a 403 or
	// 404 keeps the server's detail and still satisfies errors.Is.
	sentinel error
}

// Unwrap exposes the sentinel, if any.
func (e *APIError) Unwrap() error { return e.sentinel }

// Error names the sentinel, when there is one, ahead of the server's detail:
// the detail alone may not say "forbidden" or "not found", and CLI users and
// scripts read those words (ocidex-nnh2).
func (e *APIError) Error() string {
	if e.sentinel == nil {
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Detail)
	}
	name := e.sentinel.Error()
	if e.Detail == "" || e.Detail == name {
		return fmt.Sprintf("HTTP %d: %s", e.Status, name)
	}
	return fmt.Sprintf("HTTP %d: %s: %s", e.Status, name, e.Detail)
}

// ConflictError is returned when an ADR-042 resolver matched more than one
// visible candidate. Candidates lists them so the caller can retry one rung
// further down the qualifier ladder. It unwraps to ErrConflict, so callers that
// only test errors.Is(err, ErrConflict) keep working.
type ConflictError struct {
	Detail     string
	Candidates []LookupCandidate
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("HTTP 409: %s", e.Detail)
}

func (e *ConflictError) Unwrap() error { return ErrConflict }

// mapError converts an HTTP status code and response body into a typed error.
// It attempts to decode the huma RFC 7807 ErrorModel for the detail message.
func mapError(status int, body []byte) error {
	detail := extractDetail(body)
	switch status {
	// The detail is kept: "forbidden" alone does not tell an agent operator
	// which capability is missing (ocidex-70eo.4).
	case 403:
		return &APIError{Status: status, Detail: detail, sentinel: ErrForbidden}
	case 404:
		return &APIError{Status: status, Detail: detail, sentinel: ErrNotFound}
	case 409:
		// Only a resolver conflict carries candidates. Other 409s (a duplicate
		// registry name, say) stay the bare sentinel.
		if candidates := extractCandidates(body); len(candidates) > 0 {
			return &ConflictError{Detail: detail, Candidates: candidates}
		}
		return ErrConflict
	default:
		return &APIError{Status: status, Detail: detail}
	}
}

func extractCandidates(body []byte) []LookupCandidate {
	var conflict LookupConflictError
	if err := json.Unmarshal(body, &conflict); err != nil || conflict.Candidates == nil {
		return nil
	}
	return *conflict.Candidates
}

func extractDetail(body []byte) string {
	var model ErrorModel
	if err := json.Unmarshal(body, &model); err == nil && model.Detail != nil {
		return *model.Detail
	}
	return string(body)
}
