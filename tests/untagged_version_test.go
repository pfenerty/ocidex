package tests

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// TestUntaggedSBOMsShareOneVersion holds digest-only SBOMs (no subject version,
// no image version) to one version between them. Keyed by their own ids, each
// was a separate version: three scans of untagged digests read as three
// versions and put UUIDs in the versions table.
func TestUntaggedSBOMsShareOneVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	owner := seedUser(t, pool, 9601, "untagged-owner", "member")
	nsID := seedNamespace(t, pool, "untagged-ns", owner, "public")
	var artifactID pgtype.UUID
	is.NoErr(pool.QueryRow(ctx,
		`INSERT INTO artifact (type, name) VALUES ('container', 'docker.io/untagged') RETURNING id`).Scan(&artifactID))

	insert := func(version any, age time.Duration) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO sbom (spec_version, raw_bom, artifact_id, namespace_id, subject_version, created_at)
			VALUES ('1.6', '{}'::jsonb, $1, $2::uuid, $3, now() - $4::interval)
		`, artifactID, nsID, version, age.String())
		is.NoErr(err)
	}
	insert("1.0.0", 4*time.Hour)
	insert(nil, 3*time.Hour)
	insert(nil, 2*time.Hour)
	insert(nil, time.Hour)

	anon := pgtype.Bool{Bool: false, Valid: true}
	count, err := q.CountArtifactVersions(ctx, repository.CountArtifactVersionsParams{ArtifactID: artifactID, IsAdmin: anon})
	is.NoErr(err)
	is.Equal(count, int64(2)) // 1.0.0 and untagged

	versions, err := q.ListArtifactVersions(ctx, repository.ListArtifactVersionsParams{ArtifactID: artifactID, RowLimit: 10, IsAdmin: anon})
	is.NoErr(err)
	is.Equal(len(versions), 2)
	is.Equal(versions[0].VersionKey, "1.0.0") // a real version above the untagged group
	is.Equal(versions[1].VersionKey, "(untagged)")
	is.Equal(versions[1].SbomCount, int64(3))

	// The versions row and the per-version picker agree on its SBOM.
	var picked string
	is.NoErr(pool.QueryRow(ctx,
		`SELECT version_headline_sbom($1, '(untagged)', NULL, false)::text`, artifactID).Scan(&picked))
	is.Equal(picked, versions[1].NewestSbomID.String())
}
