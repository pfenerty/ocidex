package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

// countRow returns a fakeDB whose single-row queries scan n into the first
// destination — enough to stand in for CountOwnedPrivateRegistries.
func countRow(n int64, err error) *fakeDB {
	return &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				if err != nil {
					return err
				}
				if p, ok := dest[0].(*int64); ok {
					*p = n
				}
				return nil
			}}
		},
	}
}

func testUserID(t *testing.T) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"); err != nil {
		t.Fatalf("scanning uuid: %v", err)
	}
	return u
}

// A viewer who owns no private registry sees exactly the public set, so they
// must share the anonymous scope. Giving them "u:<id>" mints a scope the
// background warmer cannot enumerate: their dashboard then always missed the
// cache, always took the multi-minute path, and always died at the HTTP
// timeout before it could write the entry back.
func TestNormalizeStatsScopeCollapsesViewersWithoutPrivateRegistries(t *testing.T) {
	is := is.New(t)
	svc := &searchService{db: countRow(0, nil)}

	got := svc.normalizeStatsScope(context.Background(), VisibilityFilter{UserID: testUserID(t)})

	is.Equal(statsCacheKey(got), "anon")
}

func TestNormalizeStatsScopeKeepsOwnersOfPrivateRegistries(t *testing.T) {
	is := is.New(t)
	uid := testUserID(t)
	svc := &searchService{db: countRow(1, nil)}

	got := svc.normalizeStatsScope(context.Background(), VisibilityFilter{UserID: uid})

	is.Equal(statsCacheKey(got), "u:"+uuidToString(uid))
}

// Widening a viewer's scope on a failed ownership check could serve them
// another viewer's data, so the check fails closed.
func TestNormalizeStatsScopeFailsClosed(t *testing.T) {
	is := is.New(t)
	uid := testUserID(t)
	svc := &searchService{db: countRow(0, errors.New("db error"))}

	got := svc.normalizeStatsScope(context.Background(), VisibilityFilter{UserID: uid})

	is.Equal(statsCacheKey(got), "u:"+uuidToString(uid))
}

func TestNormalizeStatsScopeLeavesAdminAndAnonAlone(t *testing.T) {
	is := is.New(t)
	// A nil db would panic if either case reached the ownership query.
	svc := &searchService{}

	is.Equal(statsCacheKey(svc.normalizeStatsScope(context.Background(), VisibilityFilter{IsAdmin: true})), "admin")
	is.Equal(statsCacheKey(svc.normalizeStatsScope(context.Background(), VisibilityFilter{})), "anon")
}

// Regression: on a cache miss GetDashboardStats used to fall through to
// WarmDashboardStats, running seven table-scanning aggregates on the request
// path. They cannot finish inside the HTTP timeout, and each attempt occupied
// pool connections that in-flight requests were waiting on. A miss must be
// cheap and report itself instead.
func TestGetDashboardStatsReportsWarmingOnCacheMiss(t *testing.T) {
	is := is.New(t)
	// Any query would panic on the nil db, proving nothing was computed.
	svc := &searchService{statsCache: newStatsCache(statsCacheTTL)}

	stats, err := svc.GetDashboardStats(context.Background(), VisibilityFilter{})

	is.NoErr(err)
	is.True(stats.Warming)
	is.Equal(stats.ArtifactCount, int64(0))
}

func TestGetDashboardStatsServesWarmedEntry(t *testing.T) {
	is := is.New(t)
	svc := &searchService{statsCache: newStatsCache(statsCacheTTL)}
	svc.statsCache.set("anon", &DashboardStats{ArtifactCount: 7})

	stats, err := svc.GetDashboardStats(context.Background(), VisibilityFilter{})

	is.NoErr(err)
	is.True(!stats.Warming)
	is.Equal(stats.ArtifactCount, int64(7))
}

// The warmer fills the anonymous scope, so a signed-in viewer with no private
// registry of their own must read that entry rather than mint their own.
func TestGetDashboardStatsServesWarmedAnonEntryToOrdinaryUsers(t *testing.T) {
	is := is.New(t)
	svc := &searchService{db: countRow(0, nil), statsCache: newStatsCache(statsCacheTTL)}
	svc.statsCache.set("anon", &DashboardStats{ArtifactCount: 7})

	stats, err := svc.GetDashboardStats(context.Background(), VisibilityFilter{UserID: testUserID(t)})

	is.NoErr(err)
	is.Equal(stats.ArtifactCount, int64(7))
}
