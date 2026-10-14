package tests

import (
	"fmt"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// What a refresh pass leaves in each live rollup must be exactly what that
// rollup's aggregate defines. The swap repopulates with a positional
// `INSERT ... SELECT *`, so a column appended to a rollup table in a migration
// but in a different place in its aggregate (00064, 00077 both do this) lands
// in the wrong column without any error. This holds each live table, as the
// pass left it, against its aggregate run directly — in both directions, so a
// row the pass dropped and a row it invented both fail.
func TestRollupPassWritesExactlyWhatEachAggregateDefines(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 8406, "slim-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "slim-owner", nil)
	is.NoErr(err)
	publicSrc := discoverNS(t, pool, "slim-public", ownerID, "public")
	privateSrc := discoverNS(t, pool, "slim-private", ownerID, "private")

	// Two namespaces, shared and distinct versions, a grouped twin and the tied
	// fixture's NULL-part versions: enough shape that every rollup has rows.
	ingestInto(t, srv.URL, publicSrc, fmt.Sprintf(countSBOMTemplate, 11, 11, 11, "1.0.0", "1.0.0"), ownerKey)
	ingestInto(t, srv.URL, privateSrc, fmt.Sprintf(countSBOMTemplate, 12, 12, 12, "2.0.0", "2.0.0"), ownerKey)
	ingestInto(t, srv.URL, publicSrc, tiedSBOM(), ownerKey)

	// Findings against packages in both namespaces, so vuln_rollup and
	// sbom_vuln_rollup are compared on real rows rather than two empty sets.
	_, err = pool.Exec(t.Context(), `
		INSERT INTO vulnerability (id, canonical_id, severity) VALUES
		    ('CVE-2026-0001', 'CVE-2026-0001', 'HIGH'),
		    ('CVE-2026-0002', 'CVE-2026-0002', 'LOW');
		INSERT INTO package_vulnerability (purl, vulnerability_id) VALUES
		    ('pkg:generic/counted-lib@1.0.0', 'CVE-2026-0001'),
		    ('pkg:generic/counted-lib@2.0.0', 'CVE-2026-0002'),
		    ('pkg:generic/tied-lib@build-3', 'CVE-2026-0001');`)
	is.NoErr(err)

	refreshRollups(t, pool)

	for _, table := range []string{"component_rollup", "component_version_rollup", "license_rollup", "vuln_rollup", "sbom_vuln_rollup"} {
		aggregate, ok := repository.RollupAggregate(table)
		is.True(ok)

		var live int64
		is.NoErr(pool.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&live))

		// EXCEPT ALL in both directions: a multiset comparison, so a duplicated
		// row counts as a difference too. Array columns compare by value.
		var missing, extra int64
		is.NoErr(pool.QueryRow(t.Context(),
			fmt.Sprintf("SELECT count(*) FROM ((%s) EXCEPT ALL SELECT * FROM %s) d", aggregate, table)).Scan(&missing))
		is.NoErr(pool.QueryRow(t.Context(),
			fmt.Sprintf("SELECT count(*) FROM (SELECT * FROM %s EXCEPT ALL (%s)) d", table, aggregate)).Scan(&extra))

		if missing != 0 || extra != 0 {
			t.Errorf("%s: %d live rows; %d rows the aggregate has that the pass did not write, %d the other way",
				table, live, missing, extra)
		}
		if live == 0 {
			t.Errorf("%s: no rows, so the comparison proved nothing", table)
		}
	}
}
