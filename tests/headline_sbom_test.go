package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// headlineSBOM is one SBOM of the headline fixture.
type headlineSBOM struct {
	version  string
	arch     string
	private  bool
	packages int
	age      time.Duration // how long before the fixture's "now" it was ingested
}

// TestHeadlineSBOMIsOneSBOMEverywhere seeds one artifact whose SBOMs each tempt
// a different rule into picking it, and holds every query that shows an
// artifact's or a version's counts to the same pick. Only the expected SBOM
// carries three packages and the one finding, so each query's own output says
// which SBOM it counted.
func TestHeadlineSBOMIsOneSBOMEverywhere(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	ctx := t.Context()

	const want = "1.27.4 amd64"
	fixture := map[string]headlineSBOM{
		want:                    {version: "1.27.4", arch: "amd64", packages: 3, age: 6 * time.Hour},
		"newest build, riscv64": {version: "1.27.4", arch: "riscv64", packages: 1, age: 1 * time.Hour},
		"arm64":                 {version: "1.27.4", arch: "arm64", packages: 1, age: 2 * time.Hour},
		"no architecture":       {version: "1.27.4", packages: 1, age: 3 * time.Hour},
		"variant, same parts":   {version: "1.27.4-trixie", arch: "amd64", packages: 1, age: 30 * time.Minute},
		"newer prerelease":      {version: "1.28.0-rc.1", arch: "amd64", packages: 1, age: 10 * time.Minute},
		"older version":         {version: "1.27.3", arch: "amd64", packages: 1, age: 5 * time.Minute},
		"newer but private":     {version: "1.29.0", arch: "amd64", private: true, packages: 1, age: time.Minute},
	}

	ownerID := seedUser(t, pool, 8701, "headline-owner", "member")
	publicNS := seedNamespace(t, pool, "headline-public", ownerID, "public")
	privateNS := seedNamespace(t, pool, "headline-private", ownerID, "private")
	var artifactID pgtype.UUID
	is.NoErr(pool.QueryRow(ctx,
		`INSERT INTO artifact (type, name) VALUES ('container', 'example.test/headline') RETURNING id`).Scan(&artifactID))

	now := time.Now()
	ids := map[string]string{}
	n := 0
	for label, f := range fixture {
		ns := publicNS
		if f.private {
			ns = privateNS
		}
		ids[label] = seedHeadlineSBOM(t, pool, artifactID, ns, f, now.Add(-f.age), &n)
	}
	wantID := ids[want]

	// The finding sits on a package only the expected SBOM carries.
	seedFinding(t, pool, "CVE-2026-40001", "CRITICAL", "headline-vulnerable")
	_, err := pool.Exec(ctx, `INSERT INTO sbom_vuln_match (sbom_id, db_built_at, matched_at) VALUES ($1, now(), now() - interval '1 hour')`, wantID)
	is.NoErr(err)
	refreshRollups(t, pool)

	q := repository.New(pool)
	anon := pgtype.UUID{}
	noAdmin := pgtype.Bool{Bool: false, Valid: true}

	var picked string
	is.NoErr(pool.QueryRow(ctx, `SELECT artifact_headline_sbom($1, NULL, false)::text`, artifactID).Scan(&picked))
	is.Equal(labelOf(ids, picked), want) // artifact_headline_sbom

	match, err := q.GetLatestArtifactSBOMMatch(ctx, repository.GetLatestArtifactSBOMMatchParams{ArtifactID: artifactID, UserID: anon, IsAdmin: noAdmin})
	is.NoErr(err)
	is.Equal(match.SubjectVersion, "1.27.4")
	is.True(match.Matched)
	is.Equal(labelOf(ids, match.SbomID.String()), want)
	is.Equal(match.Architecture, "amd64") // GetLatestArtifactSBOMMatch

	summary, err := q.GetArtifactVulnSummary(ctx, repository.GetArtifactVulnSummaryParams{ArtifactID: artifactID, UserID: anon, IsAdmin: noAdmin})
	is.NoErr(err)
	is.Equal(summary.Critical, int64(1))
	is.Equal(summary.SubjectVersion, "1.27.4") // GetArtifactVulnSummary

	packages, err := q.CountLatestVersionPackages(ctx, repository.CountLatestVersionPackagesParams{ArtifactID: artifactID, UserID: anon, IsAdmin: noAdmin})
	is.NoErr(err)
	is.Equal(packages, int64(3)) // CountLatestVersionPackages

	list, err := q.ListArtifacts(ctx, repository.ListArtifactsParams{UserID: anon, IsAdmin: noAdmin, HasCursor: pgtype.Bool{Valid: true}, SortDir: 1, RowLimit: 10})
	is.NoErr(err)
	is.Equal(len(list), 1)
	is.Equal(list[0].VulnCritical, int64(1))
	is.Equal(labelOf(ids, list[0].CountedSbomID.String()), want)
	is.Equal(list[0].CountedVersion.String, "1.27.4")
	is.Equal(list[0].CountedArchitecture, "amd64") // ListArtifacts

	maxima, err := q.GetArtifactMaxima(ctx, repository.GetArtifactMaximaParams{UserID: anon, IsAdmin: noAdmin})
	is.NoErr(err)
	is.Equal(maxima.MaxPackages, int64(3))
	is.Equal(maxima.MaxCritical, int64(1)) // GetArtifactMaxima

	featured, err := q.GetDiscoverFeaturedArtifacts(ctx, repository.GetDiscoverFeaturedArtifactsParams{RowLimit: 5, Names: []string{"headline"}})
	is.NoErr(err)
	is.Equal(len(featured), 1)
	is.Equal(labelOf(ids, featured[0].SbomID.String()), want)
	is.Equal(featured[0].Architecture, "amd64") // GetDiscoverFeaturedArtifacts

	versions, err := q.ListArtifactVersions(ctx, repository.ListArtifactVersionsParams{ArtifactID: artifactID, RowLimit: 20, UserID: anon, IsAdmin: noAdmin})
	is.NoErr(err)
	// The table's own order is the version line, not ingest order (1.27.3
	// was ingested last of these).
	order := make([]string, 0, len(versions))
	for _, v := range versions {
		order = append(order, v.VersionKey)
	}
	is.Equal(order, []string{"1.28.0-rc.1", "1.27.4", "1.27.4-trixie", "1.27.3"})

	var versionRow string
	for _, v := range versions {
		if v.VersionKey == "1.27.4" {
			versionRow = v.NewestSbomID.String()
			is.Equal(v.CountedArchitecture, "amd64")
		}
	}
	is.Equal(labelOf(ids, versionRow), want) // ListArtifactVersions

	var versionPick string
	is.NoErr(pool.QueryRow(ctx, `SELECT version_headline_sbom($1, '1.27.4', NULL, false)::text`, artifactID).Scan(&versionPick))
	is.Equal(labelOf(ids, versionPick), want) // version_headline_sbom

	history, err := q.ListArtifactCriticalHistory(ctx, repository.ListArtifactCriticalHistoryParams{ArtifactIds: []pgtype.UUID{artifactID}, UserID: anon, IsAdmin: noAdmin})
	is.NoErr(err)
	is.True(len(history) > 0)
	is.Equal(history[0].Rank, int64(1))
	is.Equal(history[0].VersionKey, "1.27.4")
	is.Equal(history[0].Critical, int64(1))
	is.Equal(history[0].Architecture, "amd64") // ListArtifactCriticalHistory
}

// seedHeadlineSBOM inserts one fixture SBOM with its architecture enrichment
// and packages, and returns its id. The expected SBOM's packages include the
// vulnerable one; every other SBOM's packages are unique to it.
func seedHeadlineSBOM(t *testing.T, pool *pgxpool.Pool, artifactID pgtype.UUID, nsID string, f headlineSBOM, created time.Time, n *int) string {
	t.Helper()
	ctx := t.Context()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO sbom (spec_version, raw_bom, artifact_id, namespace_id, subject_version, created_at)
		VALUES ('1.6', '{}'::jsonb, $1, $2::uuid, $3, $4)
		RETURNING id::text
	`, artifactID, nsID, f.version, created).Scan(&id); err != nil {
		t.Fatalf("seed sbom %s: %v", f.version, err)
	}
	if f.arch != "" {
		if _, err := pool.Exec(ctx, `
			INSERT INTO enrichment (sbom_id, enricher_name, status, data)
			VALUES ($1::uuid, 'oci-metadata', 'success', jsonb_build_object('architecture', $2::text))
		`, id, f.arch); err != nil {
			t.Fatalf("seed enrichment: %v", err)
		}
	}
	for i := 0; i < f.packages; i++ {
		*n++
		name := fmt.Sprintf("headline-pkg-%d", *n)
		if f.packages == 3 && i == 0 {
			name = "headline-vulnerable"
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO component (sbom_id, type, name, version, purl)
			VALUES ($1::uuid, 'library', $2, '1.0.0', 'pkg:generic/' || $2 || '@1.0.0')
		`, id, name); err != nil {
			t.Fatalf("seed component: %v", err)
		}
	}
	return id
}

// labelOf names a fixture SBOM by id, so a failure says which wrong SBOM won.
func labelOf(ids map[string]string, id string) string {
	for label, v := range ids {
		if v == id {
			return label
		}
	}
	return "unknown sbom " + id
}
