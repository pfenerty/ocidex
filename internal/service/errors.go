// Package service contains business logic interfaces and implementations.
package service

import "errors"

// Sentinel errors for the service layer.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

// ValidationError represents a client-supplied input error.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }
