// Package service contains business logic interfaces and implementations.
package service

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Sentinel errors for the service layer.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	// ErrNamespaceExists reports that a namespace named for creation already
	// exists. Whether the caller may use it instead is for the API layer to
	// decide.
	ErrNamespaceExists = errors.New("namespace exists")
	// ErrSignupClosed reports a first sign-in refused because the installation
	// does not provision new accounts (SIGNUP_MODE=existing).
	ErrSignupClosed = errors.New("sign-up is closed")
)

// ValidationError represents a client-supplied input error.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }
