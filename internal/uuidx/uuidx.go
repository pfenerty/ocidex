// Package uuidx is the one place this module turns text into a pgtype.UUID
// (ocidex-43lo.3). The other direction needs no helper: pgtype.UUID.String
// renders the canonical form, and "" for a NULL UUID.
package uuidx

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
)

// Parse parses a UUID in its canonical 8-4-4-4-12 form, or as 32 hex digits
// with no dashes.
//
// pgtype.UUID.Scan alone accepts any 36-character string and drops whatever
// sits where the dashes belong, so a 36-hex-digit string silently became a
// different UUID; Parse checks the dashes first.
func Parse(s string) (pgtype.UUID, error) {
	if len(s) == 36 && (s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-') {
		return pgtype.UUID{}, fmt.Errorf("invalid uuid: %q", s)
	}
	var id pgtype.UUID
	if err := id.Scan(s); err != nil || !id.Valid {
		return pgtype.UUID{}, fmt.Errorf("invalid uuid: %q", s)
	}
	return id, nil
}
