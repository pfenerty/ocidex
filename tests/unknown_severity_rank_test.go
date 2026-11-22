package tests

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// TestUnknownSeverityRanksBelowLow holds every severity ordering to one rule: a
// finding with no severity is the least severe, never worse than LOW. A large
// share of findings carry none (243 of golang's 853), so ranking them above
// LOW would float images with many unrated findings over images with real
// ones. "many-unknown" carries five unrated findings, "one-low" a single LOW.
func TestUnknownSeverityRanksBelowLow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	owner := seedUser(t, pool, 9501, "unknown-rank-owner", "member")
	nsID := seedNamespace(t, pool, "unknown-rank-ns", owner, "public")

	seed := func(name string, findings map[string]string) {
		t.Helper()
		var artifactID, sbomID pgtype.UUID
		is.NoErr(pool.QueryRow(ctx,
			`INSERT INTO artifact (type, name) VALUES ('container', $1) RETURNING id`, name).Scan(&artifactID))
		is.NoErr(pool.QueryRow(ctx, `
			INSERT INTO sbom (spec_version, raw_bom, artifact_id, namespace_id, subject_version)
			VALUES ('1.6', '{}'::jsonb, $1, $2::uuid, '1.0.0') RETURNING id
		`, artifactID, nsID).Scan(&sbomID))
		for cve, sev := range findings {
			pkg := name + "-" + cve
			_, err := pool.Exec(ctx, `
				INSERT INTO component (sbom_id, type, name, version, purl)
				VALUES ($1, 'library', $2, '1.0.0', 'pkg:generic/' || $2 || '@1.0.0')
			`, sbomID, pkg)
			is.NoErr(err)
			// "" stores a NULL severity, the other way a finding arrives unrated.
			_, err = pool.Exec(ctx, `
				INSERT INTO vulnerability (id, canonical_id, severity, summary)
				VALUES ($1, $1, NULLIF($2, ''), 'seeded')
			`, cve, sev)
			is.NoErr(err)
			_, err = pool.Exec(ctx,
				`INSERT INTO package_vulnerability (purl, vulnerability_id) VALUES ('pkg:generic/' || $1 || '@1.0.0', $2)`, pkg, cve)
			is.NoErr(err)
		}
	}
	unknown := map[string]string{}
	for i := 0; i < 5; i++ {
		label := ""
		if i%2 == 1 {
			label = "UNKNOWN" // grype's literal label ranks the same as none
		}
		unknown[fmt.Sprintf("CVE-2026-8000%d", i)] = label
	}
	seed("docker.io/many-unknown", unknown)
	seed("docker.io/one-low", map[string]string{"CVE-2026-80100": "LOW"})
	refreshRollups(t, pool)

	anon := pgtype.Bool{Bool: false, Valid: true}

	// /artifacts, sorted worst first and least-bad first.
	names := func(dir int32) []string {
		t.Helper()
		rows, err := q.ListArtifacts(ctx, repository.ListArtifactsParams{
			IsAdmin: anon, HasCursor: pgtype.Bool{Valid: true}, SortSeverity: true, SortDir: dir, RowLimit: 10,
		})
		is.NoErr(err)
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return out
	}
	is.Equal(names(1), []string{"docker.io/one-low", "docker.io/many-unknown"})
	is.Equal(names(-1), []string{"docker.io/many-unknown", "docker.io/one-low"})

	// /vulnerabilities, worst first: the LOW advisory leads every unrated one.
	top, err := q.ListTopVulnerabilities(ctx, repository.ListTopVulnerabilitiesParams{
		IsAdmin: anon, SortBy: "severity", SortDir: "desc",
		RowLimit: pgtype.Int4{Int32: 10, Valid: true}, RowOffset: pgtype.Int4{Valid: true},
	})
	is.NoErr(err)
	is.Equal(len(top), 6)
	is.Equal(top[0].CanonicalID, "CVE-2026-80100")
}
