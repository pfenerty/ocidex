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
