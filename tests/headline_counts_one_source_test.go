package tests

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// TestHeadlineCountsChangeTogether holds the artifact tile, the /artifacts row
// and the featured card to one source. A finding that lands between refresh
// passes shows on none of them until the pass runs, then on all three; the
// tile used to count live and showed it a refresh interval before the row.
// "Matched" waits for the rollup the same way on the tile and the card.
func TestHeadlineCountsChangeTogether(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	owner := seedUser(t, pool, 9401, "one-source-owner", "member")
	nsID := seedNamespace(t, pool, "one-source-ns", owner, "public")
	var artifactID, sbomID pgtype.UUID
	is.NoErr(pool.QueryRow(ctx,
		`INSERT INTO artifact (type, name) VALUES ('container', 'docker.io/one-source') RETURNING id`).Scan(&artifactID))
	is.NoErr(pool.QueryRow(ctx, `
		INSERT INTO sbom (spec_version, raw_bom, artifact_id, namespace_id, subject_version)
		VALUES ('1.6', '{}'::jsonb, $1, $2::uuid, '1.0.0') RETURNING id
	`, artifactID, nsID).Scan(&sbomID))
	_, err := pool.Exec(ctx, `
		INSERT INTO component (sbom_id, type, name, version, purl)
		VALUES ($1, 'library', 'one-source', '1.0.0', 'pkg:generic/one-source@1.0.0')
	`, sbomID)
	is.NoErr(err)
	refreshRollups(t, pool)

	anon := pgtype.Bool{Bool: false, Valid: true}
	critical := func() (tile, row, card int64, tileMatched, cardMatched bool) {
		t.Helper()
		s, err := q.GetArtifactVulnSummary(ctx, repository.GetArtifactVulnSummaryParams{ArtifactID: artifactID, IsAdmin: anon})
		is.NoErr(err)
		m, err := q.GetLatestArtifactSBOMMatch(ctx, repository.GetLatestArtifactSBOMMatchParams{ArtifactID: artifactID, IsAdmin: anon})
		is.NoErr(err)
		list, err := q.ListArtifacts(ctx, repository.ListArtifactsParams{IsAdmin: anon, HasCursor: pgtype.Bool{Valid: true}, SortDir: 1, RowLimit: 10})
		is.NoErr(err)
		is.Equal(len(list), 1)
		featured, err := q.GetDiscoverFeaturedArtifacts(ctx, repository.GetDiscoverFeaturedArtifactsParams{RowLimit: 5, Names: []string{"one-source"}})
		is.NoErr(err)
		is.Equal(len(featured), 1)
		return s.Critical, list[0].VulnCritical, featured[0].CriticalCount, m.Matched, featured[0].VulnMatched
	}

	// Matched just now: the rollup may not have caught up, so nothing says clean.
	_, err = pool.Exec(ctx, `INSERT INTO sbom_vuln_match (sbom_id, db_built_at) VALUES ($1, now())`, sbomID)
	is.NoErr(err)
	_, _, _, tileMatched, cardMatched := critical()
	is.True(!tileMatched)
	is.True(!cardMatched)

	// A finding arrives between passes: no surface shows it yet.
	seedFinding(t, pool, "CVE-2026-70001", "CRITICAL", "one-source")
	tile, row, card, _, _ := critical()
	is.Equal([]int64{tile, row, card}, []int64{0, 0, 0})

	// The pass runs, and every surface shows it at once.
	refreshRollups(t, pool)
	tile, row, card, _, _ = critical()
	is.Equal([]int64{tile, row, card}, []int64{1, 1, 1})

	// No fixed version recorded: nothing fixable. Once the advisory names one,
	// the next pass counts it on the tile and the row alike.
	fixable := func() (tile, row int64) {
		t.Helper()
		sum, err := q.GetArtifactVulnSummary(ctx, repository.GetArtifactVulnSummaryParams{ArtifactID: artifactID, IsAdmin: anon})
		is.NoErr(err)
		list, err := q.ListArtifacts(ctx, repository.ListArtifactsParams{IsAdmin: anon, HasCursor: pgtype.Bool{Valid: true}, SortDir: 1, RowLimit: 10})
		is.NoErr(err)
		return sum.Fixable, list[0].VulnFixable
	}
	tf, rf := fixable()
	is.Equal([]int64{tf, rf}, []int64{0, 0})
	_, err = pool.Exec(ctx, `UPDATE package_vulnerability SET fixed_version = '1.0.1' WHERE vulnerability_id = 'CVE-2026-70001'`)
	is.NoErr(err)
	refreshRollups(t, pool)
	tf, rf = fixable()
	is.Equal([]int64{tf, rf}, []int64{1, 1})

	// Once the match is two refresh intervals old, it counts as settled.
	_, err = pool.Exec(ctx, `UPDATE sbom_vuln_match SET matched_at = now() - interval '1 hour' WHERE sbom_id = $1`, sbomID)
	is.NoErr(err)
	_, _, _, tileMatched, cardMatched = critical()
	is.True(tileMatched)
	is.True(cardMatched)
}
