package api

import (
	"github.com/jackc/pgx/v5/pgtype"
)

// ParseUUID parses a string into a pgtype.UUID, returning a huma 400 error on failure.
//
// Deprecated: Use the unexported parseUUID instead. This remains exported only
// for backward compatibility with existing tests.
func ParseUUID(s string) (pgtype.UUID, error) {
	return parseUUID(s)
}
