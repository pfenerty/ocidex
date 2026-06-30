package service

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

func TestStatsCacheHitAndExpiry(t *testing.T) {
	is := is.New(t)

	now := time.Unix(0, 0)
	c := newStatsCache(60 * time.Second)
	c.now = func() time.Time { return now }

	stats := &DashboardStats{SBOMCount: 7}
	c.set("anon", stats)

	// Hit within TTL.
	is.Equal(c.get("anon"), stats)

	// Still valid just before expiry.
	now = now.Add(59 * time.Second)
	is.Equal(c.get("anon"), stats)

	// Expired after TTL.
	now = now.Add(2 * time.Second)
	is.Equal(c.get("anon"), (*DashboardStats)(nil))
}

func TestStatsCacheKeyByScope(t *testing.T) {
	is := is.New(t)

	uid := pgtype.UUID{Bytes: [16]byte{1, 2, 3}, Valid: true}

	is.Equal(statsCacheKey(VisibilityFilter{IsAdmin: true}), "admin")
	is.Equal(statsCacheKey(VisibilityFilter{IsAdmin: true, UserID: uid}), "admin")
	is.Equal(statsCacheKey(VisibilityFilter{UserID: uid}), "u:"+uuidToString(uid))
	is.Equal(statsCacheKey(VisibilityFilter{}), "anon")
}
