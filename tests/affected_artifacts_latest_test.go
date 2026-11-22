package tests

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// TestAffectedArtifactsCountLatestVersion holds "affects N artifacts" to the
// rule every artifact row uses: an artifact is affected when the SBOM it is
// counted from is. "fixed" carried the CVE in 1.0.0 and shipped 1.1.0 without
// it; "still" carries it in its latest version and in two older ones.
func TestAffectedArtifactsCountLatestVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	const (
		vulnPurl  = "pkg:generic/blast-vulnerable@1.0.0"
		cleanPurl = "pkg:generic/blast-clean@1.0.0"
		canonical = "CVE-2026-60001"
	)
	owner := seedUser(t, pool, 9301, "blast-owner", "member")
	nsID := seedNamespace(t, pool, "blast-ns", owner, "public")

	now := time.Now()
	fixed := seedBlastArtifact(t, pool, "docker.io/fixed")
	seedBlastSBOM(t, pool, nsID, fixed, "1.0.0", vulnPurl, now.Add(-2*time.Hour))
	seedBlastSBOM(t, pool, nsID, fixed, "1.1.0", cleanPurl, now.Add(-time.Hour))

	still := seedBlastArtifact(t, pool, "docker.io/still")
	seedBlastSBOM(t, pool, nsID, still, "2.0.0", vulnPurl, now.Add(-3*time.Hour))
	seedBlastSBOM(t, pool, nsID, still, "2.1.0", vulnPurl, now.Add(-2*time.Hour))
	seedBlastSBOM(t, pool, nsID, still, "2.2.0", vulnPurl, now.Add(-time.Hour))

	seedAdvisory(t, pool, "GHSA-blast", canonical, "HIGH", 7.5, vulnPurl)
	refreshRollups(t, pool)

	rows, err := q.ListAffectedArtifactsByVuln(ctx, repository.ListAffectedArtifactsByVulnParams{
		CanonicalID: canonical,
		RowLimit:    pgtype.Int4{Int32: 20, Valid: true},
		RowOffset:   pgtype.Int4{Valid: true},
	})
	is.NoErr(err)
	is.Equal(len(rows), 2)
	is.Equal(rows[0].Name, "docker.io/still") // latest-affected first
	is.True(rows[0].LatestAffected)
	is.Equal(rows[0].OlderVersionCount, int64(2))
	is.Equal(rows[0].AffectedSbomCount, int64(3))
	is.Equal(rows[1].Name, "docker.io/fixed")
	is.True(!rows[1].LatestAffected)
	is.Equal(rows[1].OlderVersionCount, int64(1))
	is.Equal(rows[0].LatestCount, int64(1))
	is.Equal(rows[0].SupersededCount, int64(1))

	discover, err := q.GetDiscoverTopVulnerabilities(ctx, repository.GetDiscoverTopVulnerabilitiesParams{CandidateLimit: 10, RowLimit: 10})
	is.NoErr(err)
	is.Equal(len(discover), 1)
	is.Equal(discover[0].AffectedArtifactCount, int64(1)) // "still" only

	// The endpoint lists latest-affected artifacts by default and names the
	// rest; allVersions lists them too.
	srv, _ := setupServerWithAuth(t, pool)
	defer srv.Close()
	type detail struct {
		AffectedArtifacts []struct {
			Name           string `json:"name"`
			LatestAffected bool   `json:"latestAffected"`
		} `json:"affectedArtifacts"`
		Pagination              struct{ Total int64 } `json:"pagination"`
		SupersededArtifactCount int64                 `json:"supersededArtifactCount"`
	}
	var latest, all detail
	getJSON(t, srv.URL+"/api/v1/vulns/"+canonical, "", &latest)
	is.Equal(len(latest.AffectedArtifacts), 1)
	is.Equal(latest.AffectedArtifacts[0].Name, "docker.io/still")
	is.Equal(latest.Pagination.Total, int64(1))
	is.Equal(latest.SupersededArtifactCount, int64(1))
	getJSON(t, srv.URL+"/api/v1/vulns/"+canonical+"?allVersions=true", "", &all)
	is.Equal(len(all.AffectedArtifacts), 2)
	is.Equal(all.Pagination.Total, int64(2))
}

// seedBlastArtifact inserts a container artifact and returns its id.
func seedBlastArtifact(t *testing.T, pool *pgxpool.Pool, name string) pgtype.UUID {
	t.Helper()
	var id pgtype.UUID
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO artifact (type, name) VALUES ('container', $1) RETURNING id`, name).Scan(&id); err != nil {
		t.Fatalf("seed artifact %q: %v", name, err)
	}
	return id
}

// seedBlastSBOM inserts one version of an artifact carrying one package.
func seedBlastSBOM(t *testing.T, pool *pgxpool.Pool, nsID string, artifactID pgtype.UUID, version, purl string, created time.Time) {
	t.Helper()
	ctx := t.Context()
	var sbomID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO sbom (spec_version, raw_bom, artifact_id, namespace_id, subject_version, created_at)
		VALUES ('1.6', '{}'::jsonb, $1, $2::uuid, $3, $4) RETURNING id::text
	`, artifactID, nsID, version, created).Scan(&sbomID); err != nil {
		t.Fatalf("seed sbom %s: %v", version, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component (sbom_id, type, name, version, purl)
		VALUES ($1::uuid, 'library', 'blast', '1.0.0', $2)
	`, sbomID, purl); err != nil {
		t.Fatalf("seed component: %v", err)
	}
}
