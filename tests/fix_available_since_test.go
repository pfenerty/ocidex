package tests

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/vuln"
)

// TestFixAvailableSince follows one mapping through the refresher's merges:
// set when first reported fixed, kept across later builds, cleared when the
// fix is withdrawn.
func TestFixAvailableSince(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	ctx := t.Context()
	store := vuln.NewPGStore(pool)

	const purl = "pkg:generic/fixme@1.0.0"
	seedAdvisory(t, pool, "CVE-2031-3001", "CVE-2031-3001", "HIGH", 7.0, "pkg:generic/unrelated@0")

	since := func() pgtype.Timestamptz {
		t.Helper()
		var ts pgtype.Timestamptz
		if err := pool.QueryRow(ctx,
			`SELECT fix_available_since FROM package_vulnerability WHERE purl = $1 AND vulnerability_id = 'CVE-2031-3001'`,
			purl).Scan(&ts); err != nil {
			t.Fatal(err)
		}
		return ts
	}
	merge := func(fixed, state string, built time.Time) {
		t.Helper()
		is.NoErr(store.MergePackageVulns(ctx, purl, []vuln.PackageVulnRef{
			{VulnerabilityID: "CVE-2031-3001", FixedVersion: fixed, FixState: state},
		}, built))
	}

	b1 := time.Now().Add(-3 * time.Hour)
	merge("", "not-fixed", b1)
	is.True(!since().Valid) // not fixed yet

	b2 := b1.Add(time.Hour)
	merge("1.0.1", "fixed", b2)
	first := since()
	is.True(first.Valid)

	// A later build that still reports it fixed keeps the first time.
	merge("1.0.1", "fixed", b2.Add(time.Hour))
	is.Equal(since().Time, first.Time)

	// A withdrawn fix clears it.
	merge("", "not-fixed", b2.Add(2*time.Hour))
	is.True(!since().Valid)
}

// TestFixAvailableSinceBackfillIdempotent reruns the migration's backfill: a
// legacy fixed row (no fix_state) gets updated_at, and running it again
// changes nothing.
func TestFixAvailableSinceBackfillIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	ctx := t.Context()

	seedAdvisory(t, pool, "CVE-2031-3002", "CVE-2031-3002", "HIGH", 7.0, "pkg:generic/legacy@1")
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	// Simulate a row from before the column: fixed version, no state, no time.
	_, err := pool.Exec(ctx, `ALTER TABLE package_vulnerability DISABLE TRIGGER package_vuln_track_fix`)
	is.NoErr(err)
	_, err = pool.Exec(ctx, `UPDATE package_vulnerability SET fixed_version = '2', fix_state = NULL,
		fix_available_since = NULL, updated_at = $1 WHERE vulnerability_id = 'CVE-2031-3002'`, stamp)
	is.NoErr(err)
	_, err = pool.Exec(ctx, `ALTER TABLE package_vulnerability ENABLE TRIGGER package_vuln_track_fix`)
	is.NoErr(err)

	backfill := `UPDATE package_vulnerability SET fix_available_since = updated_at
		WHERE fix_available_since IS NULL AND package_vuln_is_fixed(fix_state, fixed_version)`
	read := func() time.Time {
		var ts time.Time
		is.NoErr(pool.QueryRow(ctx,
			`SELECT fix_available_since FROM package_vulnerability WHERE vulnerability_id = 'CVE-2031-3002'`).Scan(&ts))
		return ts
	}
	_, err = pool.Exec(ctx, backfill)
	is.NoErr(err)
	is.True(read().Equal(stamp))
	tag, err := pool.Exec(ctx, backfill)
	is.NoErr(err)
	is.Equal(tag.RowsAffected(), int64(0))
	is.True(read().Equal(stamp))
}
