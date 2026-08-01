// Package repository provides the data access layer for OCIDex.
//
// This file holds the maintenance SQL that rebuilds the list-page rollup tables
// (ocidex-ckv.2). It is hand-written rather than generated because sqlc models
// queries that return rows into a caller; these are DDL and bulk DML executed
// for their effect, and the aggregate text has to be interpolated into a
// CREATE TEMP TABLE ... AS, which sqlc has no way to express.
//
// The three aggregate statements below are the definition of the rollups. The
// seeding INSERTs in db/migrations/00051_list_rollups.sql are the same queries
// and must be kept in step with these: a divergence would leave the rollup
// correct immediately after migration and wrong after the first refresh, which
// is the hardest version of this bug to notice.
package repository

import (
	"context"
	"fmt"
	"time"
)

// RollupRefreshLockName is hashed into the advisory lock key that makes a
// refresh pass single-flight across replicas. Exported so the caller derives
// the key the same way the poller and reverifier derive theirs.
const RollupRefreshLockName = "ocidex-rollup-refresh"

// rollupTargets lists each rollup table with the aggregate that defines it, in
// the order a pass rebuilds them.
var rollupTargets = []struct {
	table     string
	aggregate string
}{
	{"component_rollup", componentRollupAggregate},
	{"license_rollup", licenseRollupAggregate},
	{"vuln_rollup", vulnRollupAggregate},
}

// One row per (namespace, package identity). array_agg(DISTINCT c.version) keeps
// a NULL version as an array element on purpose: a component with no recorded
// version is a distinct thing from one versioned "", and the read queries
// distinguish them.
const componentRollupAggregate = `
SELECT s.namespace_id, c.type, c.name, c.group_name,
       COALESCE(array_agg(DISTINCT split_part(replace(c.purl, 'pkg:', ''), '/', 1))
                FILTER (WHERE c.purl IS NOT NULL), '{}')::text[] AS purl_types,
       array_agg(DISTINCT c.version)::text[] AS versions,
       count(DISTINCT c.sbom_id)::bigint AS sbom_count
FROM component c
JOIN sbom s ON s.id = c.sbom_id
GROUP BY s.namespace_id, c.type, c.name, c.group_name`

// Distinct (license, namespace, component identity) triples. The identity is the
// same four-part tuple ListLicenses used to count distinct, pre-joined with a
// unit separator so the read side counts one text column instead of a row
// constructor.
const licenseRollupAggregate = `
SELECT DISTINCT cl.license_id, s.namespace_id,
       c.name || E'\x1f' || COALESCE(c.group_name, '') || E'\x1f' || COALESCE(c.version, '') || E'\x1f' || c.type AS identity_key
FROM component_license cl
JOIN component c ON c.id = cl.component_id
JOIN sbom s ON s.id = c.sbom_id`

// One row per (canonical vulnerability, namespace). purls is a set because the
// same package can be affected in several namespaces and the list reports a
// count distinct across all of them.
const vulnRollupAggregate = `
SELECT v.canonical_id, s.namespace_id,
       count(DISTINCT comp.sbom_id)::bigint AS sbom_count,
       array_agg(DISTINCT pv.purl)::text[] AS purls
FROM vulnerability v
JOIN package_vulnerability pv ON pv.vulnerability_id = v.id
JOIN component comp ON comp.purl = pv.purl
JOIN sbom s ON s.id = comp.sbom_id
WHERE v.canonical_id <> '' AND comp.purl IS NOT NULL
GROUP BY v.canonical_id, s.namespace_id`

// RollupWatermark summarises the ingest state the rollups were built from. Two
// passes that observe the same watermark would compute the same component and
// license rollups, so the second can be skipped.
//
// It covers ingest only. package_vulnerability grows whenever the vulnerability
// feed updates, with no new SBOM to move the watermark, so vuln_rollup can go
// stale without this noticing — that is what the unconditional backstop interval
// is for. Ingest gets the fast path because it is the one a user watches: they
// push an SBOM and immediately look for its packages.
type RollupWatermark struct {
	SBOMs  int64
	Latest time.Time
}

// ReadRollupWatermark reads the current watermark. This is a count and a max
// over sbom — thousands of rows, not the ten million in component — so it is
// cheap enough to poll at a much finer cadence than a rebuild.
func ReadRollupWatermark(ctx context.Context, db DBTX) (RollupWatermark, error) {
	var w RollupWatermark
	const q = `SELECT count(*), COALESCE(max(created_at), '-infinity'::timestamptz) FROM sbom`
	if err := db.QueryRow(ctx, q).Scan(&w.SBOMs, &w.Latest); err != nil {
		return RollupWatermark{}, fmt.Errorf("reading rollup watermark: %w", err)
	}
	return w, nil
}

// TryLockRollupRefresh takes the transaction-scoped advisory lock guarding a
// refresh pass, returning false if another pass already holds it.
//
// The lock is transactional rather than session-scoped so it cannot outlive the
// work: a session lock on a background pool of two connections would pin one of
// them for the process lifetime, and a crashed pass would keep the lock until
// its connection was reaped.
func TryLockRollupRefresh(ctx context.Context, db DBTX, key int64) (bool, error) {
	var acquired bool
	if err := db.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", key).Scan(&acquired); err != nil {
		return false, fmt.Errorf("taking rollup refresh lock: %w", err)
	}
	return acquired, nil
}

// BuildRollupSnapshots materialises every rollup into a temp table. This is the
// expensive part of a pass — minutes of sequential scans over the component
// table — and it deliberately happens before any lock on the live tables is
// taken, so readers are unaffected while it runs.
func BuildRollupSnapshots(ctx context.Context, db DBTX) error {
	for _, t := range rollupTargets {
		stmt := fmt.Sprintf("CREATE TEMP TABLE %s ON COMMIT DROP AS %s", tempName(t.table), t.aggregate)
		if _, err := db.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("building %s snapshot: %w", t.table, err)
		}
	}
	return nil
}

// SwapRollupSnapshots replaces the live rollups with the snapshots built by
// BuildRollupSnapshots.
//
// TRUNCATE takes ACCESS EXCLUSIVE, which blocks every reader of the table, so
// all three swaps are deferred to here and run back to back: the lock window is
// a truncate plus an insert of a few hundred thousand already-computed rows,
// well under a second, instead of the minutes the aggregates take. The caller
// is expected to have set a lock_timeout so a pass that cannot get in fails
// rather than queueing behind a long read while holding the earlier truncates.
func SwapRollupSnapshots(ctx context.Context, db DBTX) error {
	for _, t := range rollupTargets {
		if _, err := db.Exec(ctx, "TRUNCATE "+t.table); err != nil {
			return fmt.Errorf("truncating %s: %w", t.table, err)
		}
		stmt := fmt.Sprintf("INSERT INTO %s SELECT * FROM %s", t.table, tempName(t.table))
		if _, err := db.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("repopulating %s: %w", t.table, err)
		}
	}
	return nil
}

func tempName(table string) string { return "tmp_" + table }
