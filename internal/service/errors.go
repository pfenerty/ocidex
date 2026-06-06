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
)

// ValidationError represents a client-supplied input error.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }
