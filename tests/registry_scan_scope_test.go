package tests

import (
	"testing"

	"github.com/matryer/is"
	"github.com/pressly/goose/v3"
)

// TestScanScopeMigrationDefaultsExistingRegistries covers ADR-0053 S5: a
// registry that existed before 00081 comes out with tag_limit 50 and the auto
// order, so its next poll stops backfilling.
func TestScanScopeMigrationDefaultsExistingRegistries(t *testing.T) {
	requireTestInfra(t)
	is := is.New(t)
	sqlDB := openMigrationDB(t)

	is.NoErr(goose.UpTo(sqlDB, "migrations", 80))
	_, err := sqlDB.ExecContext(t.Context(), `
		WITH ns AS (
			INSERT INTO namespace (name, visibility) VALUES ('pre-0053', 'public') RETURNING id
		), src AS (
			INSERT INTO source (id, namespace_id, kind, name)
			SELECT id, id, 'oci_registry', 'pre-0053' FROM ns RETURNING id
		)
		INSERT INTO registry (id, type, url, scan_mode)
		SELECT id, 'generic', 'registry.example', 'poll' FROM src`)
	is.NoErr(err)

	is.NoErr(goose.UpTo(sqlDB, "migrations", 81))
	var (
		limit  int
		order  *string
		maxAge *int
	)
	is.NoErr(sqlDB.QueryRowContext(t.Context(),
		`SELECT tag_limit, tag_order, max_tag_age_days FROM registry`).Scan(&limit, &order, &maxAge))
	is.Equal(limit, 50)
	is.True(order == nil)
	is.True(maxAge == nil)

	_, err = sqlDB.ExecContext(t.Context(), `UPDATE registry SET tag_order = 'newest'`)
	is.True(err != nil) // the check constraint rejects an unknown order

	is.NoErr(goose.DownTo(sqlDB, "migrations", 80))
}

// TestScanJobsAcceptPruned covers 00082: scan_jobs takes the 'pruned'
// tombstone, and the Down turns tombstones back into the 'succeeded' rows they
// were before the delete.
func TestScanJobsAcceptPruned(t *testing.T) {
	requireTestInfra(t)
	is := is.New(t)
	sqlDB := openMigrationDB(t)

	is.NoErr(goose.UpTo(sqlDB, "migrations", 82))
	_, err := sqlDB.ExecContext(t.Context(),
		`INSERT INTO scan_jobs (repository, digest, state) VALUES ('app', 'sha256:a', 'pruned')`)
	is.NoErr(err)

	is.NoErr(goose.DownTo(sqlDB, "migrations", 81))
	var state string
	is.NoErr(sqlDB.QueryRowContext(t.Context(), `SELECT state FROM scan_jobs`).Scan(&state))
	is.Equal(state, "succeeded")
}
