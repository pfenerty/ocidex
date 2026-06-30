package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// timeIDCursor is an opaque keyset cursor for lists ordered by
// (created_at DESC, id DESC). It is serialized to base64(JSON) and treated as
// fully opaque by clients: they receive it as nextCursor and pass it back
// unchanged. Keyset paging avoids both the OFFSET scan-and-discard cost on deep
// pages and the COUNT(*) OVER() full-set materialization on every page.
type timeIDCursor struct {
	CreatedAt time.Time `json:"t"`
	ID        string    `json:"i"`
}

// encodeTimeIDCursor builds the opaque cursor pointing just past the given row.
func encodeTimeIDCursor(createdAt time.Time, id string) string {
	b, _ := json.Marshal(timeIDCursor{CreatedAt: createdAt, ID: id})
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeTimeIDCursor parses an opaque cursor. An empty string yields a zero
// cursor (the first page) with ok=false so callers can distinguish "no cursor".
func decodeTimeIDCursor(s string) (cur timeIDCursor, ok bool, err error) {
	if s == "" {
		return timeIDCursor{}, false, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return timeIDCursor{}, false, fmt.Errorf("invalid cursor: %w", err)
	}
	if err := json.Unmarshal(b, &cur); err != nil {
		return timeIDCursor{}, false, fmt.Errorf("invalid cursor: %w", err)
	}
	return cur, true, nil
}

// derefOr returns *p, or def when p is nil. Used to fold an optional cursor key
// (e.g. a nullable group name) to a comparable value.
func derefOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

// encodeStringCursor builds an opaque cursor from an ordered tuple of string
// keys (e.g. (name, type, id)), for lists keyset-paginated on text columns plus
// an id tiebreaker. The parts must match the ORDER BY columns in order.
func encodeStringCursor(parts ...string) string {
	b, _ := json.Marshal(parts)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeStringCursor parses a string-tuple cursor. An empty string yields nil
// with ok=false (the first page). It validates that the decoded tuple has the
// expected arity so a malformed cursor can't produce a short slice.
func decodeStringCursor(s string, arity int) (parts []string, ok bool, err error) {
	if s == "" {
		return nil, false, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, false, fmt.Errorf("invalid cursor: %w", err)
	}
	if err := json.Unmarshal(b, &parts); err != nil {
		return nil, false, fmt.Errorf("invalid cursor: %w", err)
	}
	if len(parts) != arity {
		return nil, false, fmt.Errorf("invalid cursor: expected %d keys, got %d", arity, len(parts))
	}
	return parts, true, nil
}
