package tests

import (
	"context"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/service"
)

// TestMigrateBackfill runs `ocidex migrate backfill`'s pass (service.Backfill)
// over rows seeded in their pre-ingest-rule shape, against the real paged
// queries in db/queries/sbom.sql (ocidex-bt62.1).
func TestMigrateBackfill(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	is := is.New(t)
	ctx := context.Background()

	const rawBom = `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"components": [
			{"bom-ref": "located", "type": "library", "name": "github.com/legacy/svc",
			 "purl": "pkg:golang/github.com/legacy/svc@v0.9.0",
			 "properties": [
				{"name": "syft:location:0:layerID", "value": "sha256:layer1"},
				{"name": "syft:location:0:path", "value": "/usr/bin/svc"},
				{"name": "syft:package:foundBy", "value": "go-module-binary-cataloger"}
			 ]},
			{"bom-ref": "unlocated", "type": "library", "name": "github.com/legacy/lib",
			 "purl": "pkg:golang/github.com/legacy/lib@v1.0.0"}
		]
	}`

	var namespaceID, artifactID string
	is.NoErr(pool.QueryRow(ctx,
		`INSERT INTO namespace (name, visibility) VALUES ('backfill-ns', 'private') RETURNING id::text`,
	).Scan(&namespaceID))
	is.NoErr(pool.QueryRow(ctx,
		`INSERT INTO artifact (type, name) VALUES ('container', 'legacy/svc') RETURNING id::text`,
	).Scan(&artifactID))

	// Three SBOMs with no flavor, so the flavor and provenance steps each span
	// more than one page at batch size 2.
	sboms := make([]string, 3)
	for i := range sboms {
		is.NoErr(pool.QueryRow(ctx,
			`INSERT INTO sbom (artifact_id, namespace_id, spec_version, version, raw_bom, subject_version)
			 VALUES ($1, $2, '1.6', 1, $3::jsonb, 'v0.9.0') RETURNING id::text`,
			artifactID, namespaceID, rawBom,
		).Scan(&sboms[i]))
		_, err := pool.Exec(ctx,
			`INSERT INTO component (sbom_id, type, name, version, purl, bom_ref) VALUES
			   ($1, 'library', 'github.com/legacy/svc', 'v0.9.0', 'pkg:golang/github.com/legacy/svc', 'located'),
			   ($1, 'library', 'github.com/legacy/lib', 'v1.0.0', 'pkg:golang/github.com/legacy/lib@v1.0.0', 'unlocated')`,
			sboms[i])
		is.NoErr(err)
	}

	res, err := service.Backfill(ctx, repository.New(pool), 2)
	is.NoErr(err)
	is.Equal(res.Flavor, service.BackfillCounts{Updated: 3})
	is.Equal(res.Purl, service.BackfillCounts{Updated: 3})
	is.Equal(res.Provenance, service.BackfillCounts{Updated: 3, Skipped: 3})

	var unflavored, unversioned, located, unlocated int
	is.NoErr(pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM sbom WHERE flavor IS NULL OR flavor = ''),
		(SELECT count(*) FROM component WHERE purl = 'pkg:golang/github.com/legacy/svc'),
		(SELECT count(*) FROM component WHERE bom_ref = 'located' AND file_path = '/usr/bin/svc' AND layer_id = 'sha256:layer1'),
		(SELECT count(*) FROM component WHERE bom_ref = 'unlocated' AND file_path IS NULL)`,
	).Scan(&unflavored, &unversioned, &located, &unlocated))
	is.Equal(unflavored, 0)
	is.Equal(unversioned, 0)
	is.Equal(located, 3)
	is.Equal(unlocated, 3) // the SBOM records no location for it

	// A second run writes nothing: only the unlocated components are
	// re-selected, and the rule leaves them as they are.
	again, err := service.Backfill(ctx, repository.New(pool), 2)
	is.NoErr(err)
	is.Equal(again, service.BackfillResult{Provenance: service.BackfillCounts{Skipped: 3}})
}
