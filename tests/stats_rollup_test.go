package tests

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// The dashboard's growth timelines and vulnerability totals moved from
// aggregates over component to the rollups (ocidex-kf1p.5). These are the
// queries they replaced, kept here as the reference: the move is a performance
// change, so each figure must come out exactly as it did before. $1 is the
// viewer (NULL for anonymous), $2 is_admin.
const (
	oldPackageTimeline = `
WITH visible_sbom AS (
    SELECT s.id, s.created_at FROM sbom s
    WHERE s.namespace_id IN (SELECT visible_namespace_ids($1, $2))
), pkg_first_seen AS (
    SELECT DATE(MIN(vs.created_at)) AS first_seen
    FROM component c JOIN visible_sbom vs ON vs.id = c.sbom_id
    GROUP BY c.name, COALESCE(c.group_name, ''), c.type
), daily_new AS (
    SELECT first_seen, COUNT(*)::bigint AS new_count FROM pkg_first_seen
    WHERE first_seen <= CURRENT_DATE GROUP BY first_seen
)
SELECT first_seen::text, SUM(new_count) OVER (ORDER BY first_seen)::bigint
FROM daily_new ORDER BY first_seen`

	oldVersionTimeline = `
WITH visible_sbom AS (
    SELECT s.id, s.created_at FROM sbom s
    WHERE s.namespace_id IN (SELECT visible_namespace_ids($1, $2))
), ver_first_seen AS (
    SELECT DATE(MIN(vs.created_at)) AS first_seen
    FROM component c JOIN visible_sbom vs ON vs.id = c.sbom_id
    GROUP BY c.name, COALESCE(c.group_name, ''), COALESCE(c.version, ''), c.type
), daily_new AS (
    SELECT first_seen, COUNT(*)::bigint AS new_count FROM ver_first_seen
    WHERE first_seen <= CURRENT_DATE GROUP BY first_seen
)
SELECT first_seen::text, SUM(new_count) OVER (ORDER BY first_seen)::bigint
FROM daily_new ORDER BY first_seen`

	oldVulnTotal = `
SELECT COUNT(DISTINCT v.canonical_id)::bigint
FROM component c
JOIN sbom s ON s.id = c.sbom_id
JOIN package_vulnerability pv ON pv.purl = c.purl AND pv.go_symbol_set_id = COALESCE(c.go_symbol_set_id, 0)
JOIN vulnerability v ON v.id = pv.vulnerability_id
WHERE c.purl IS NOT NULL
  AND s.namespace_id IN (SELECT visible_namespace_ids($1, $2))`
)

func referenceTimeline(t *testing.T, pool *pgxpool.Pool, query string, admin bool) []service.DailyCount {
	t.Helper()
	rows, err := pool.Query(t.Context(), query, nil, admin)
	if err != nil {
		t.Fatalf("reference timeline: %v", err)
	}
	defer rows.Close()
	var out []service.DailyCount
	for rows.Next() {
		var d service.DailyCount
		if err := rows.Scan(&d.Day, &d.Count); err != nil {
			t.Fatalf("scanning reference timeline: %v", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reference timeline rows: %v", err)
	}
	return out
}

func TestDashboardStatsFromRollupsMatchTheComponentAggregates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc, searchSvc := setupServerWithStats(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 8407, "stats-rollup-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "stats-rollup-owner", nil)
	is.NoErr(err)
	publicSrc := discoverNS(t, pool, "stats-rollup-public", ownerID, "public")
	privateSrc := discoverNS(t, pool, "stats-rollup-private", ownerID, "private")

	ingestInto(t, srv.URL, publicSrc, fmt.Sprintf(countSBOMTemplate, 31, 31, 31, "1.0.0", "1.0.0"), ownerKey)
	ingestInto(t, srv.URL, privateSrc, fmt.Sprintf(countSBOMTemplate, 32, 32, 32, "2.0.0", "2.0.0"), ownerKey)
	ingestInto(t, srv.URL, publicSrc, tiedSBOM(), ownerKey)

	// Spread first-seen across days, so the timelines have more than one point
	// and a wrong MIN would move a package to the wrong one.
	_, err = pool.Exec(t.Context(), `
		UPDATE sbom SET created_at = now() - interval '3 days'
		WHERE serial_number = 'urn:uuid:88888888-8888-8888-8888-888888888831';
		UPDATE sbom SET created_at = now() - interval '1 day'
		WHERE serial_number = 'urn:uuid:88888888-8888-8888-8888-888888888832';
		INSERT INTO vulnerability (id, canonical_id, severity) VALUES
		    ('CVE-2026-0101', 'CVE-2026-0101', 'HIGH'),
		    ('GHSA-aaaa-bbbb-cccc', 'CVE-2026-0101', 'MEDIUM'),
		    ('CVE-2026-0102', 'CVE-2026-0102', 'CRITICAL');
		INSERT INTO package_vulnerability (purl, vulnerability_id) VALUES
		    ('pkg:generic/counted-lib@1.0.0', 'CVE-2026-0101'),
		    ('pkg:generic/counted-lib@1.0.0', 'GHSA-aaaa-bbbb-cccc'),
		    ('pkg:generic/counted-lib@2.0.0', 'CVE-2026-0102');`)
	is.NoErr(err)

	refreshRollups(t, pool)

	for _, admin := range []bool{false, true} {
		stats, err := searchSvc.WarmDashboardStats(t.Context(), service.VisibilityFilter{IsAdmin: admin})
		is.NoErr(err)

		is.Equal(stats.PackageGrowthTimeline, referenceTimeline(t, pool, oldPackageTimeline, admin))
		is.Equal(stats.VersionGrowthTimeline, referenceTimeline(t, pool, oldVersionTimeline, admin))
		is.True(len(stats.VersionGrowthTimeline) >= 2) // the backdating took effect

		var wantVulns int64
		is.NoErr(pool.QueryRow(t.Context(), oldVulnTotal, nil, admin).Scan(&wantVulns))
		is.Equal(stats.VulnCount, wantVulns)

		// The alias pair is one finding, in one bucket: the severity the
		// /vulnerabilities list shows for it, not one count per record.
		sev := stats.VulnSeverity
		is.Equal(sev.Critical+sev.High+sev.Medium+sev.Low+sev.Unknown, stats.VulnCount)
		is.Equal(sev.Medium, int64(0))
		if admin {
			is.Equal(stats.VulnCount, int64(2))
			is.Equal(sev.Critical, int64(1)) // only reachable through the private namespace
		} else {
			is.Equal(stats.VulnCount, int64(1))
			is.Equal(sev.High, int64(1))
		}

		// Every tied-lib version is MIT and public, so the permissive bucket
		// counts the nine distinct versions however the viewer is scoped.
		var permissive int64
		for _, c := range stats.LicenseCategories {
			if c.Category == "permissive" {
				permissive = c.ComponentCount
			}
		}
		is.Equal(permissive, int64(tiedComponentCount))
	}
}
