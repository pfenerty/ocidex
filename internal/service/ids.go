package service

import (
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/uuidx"
)

// parseID turns an ID a caller handed the service into the database's UUID
// type. Services take IDs as strings at their boundary, so callers (the HTTP
// layer above all) never name a persistence type (ocidex-8xij.4). A malformed
// ID is the caller's mistake: a ValidationError, which the API answers 400.
func parseID(s string) (pgtype.UUID, error) {
	id, err := uuidx.Parse(s)
	if err != nil {
		return pgtype.UUID{}, &ValidationError{Message: "invalid UUID: " + s}
	}
	return id, nil
}

// parseIDs is parseID for a list.
func parseIDs(ss []string) ([]pgtype.UUID, error) {
	out := make([]pgtype.UUID, len(ss))
	for i, s := range ss {
		id, err := parseID(s)
		if err != nil {
			return nil, err
		}
		out[i] = id
	}
	return out, nil
}
