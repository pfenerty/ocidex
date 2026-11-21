package tests

import (
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/enrichment/names"
	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/service"
)

// TestBackfillRootEnrichment covers ocidex-n1z4.3 against the real query: an
// SBOM with no job and no result for a root enricher gets that job; one
// enriched under the retired 'all' job (results, no job rows) or already
// enqueued is left alone; a second run is a no-op.
func TestBackfillRootEnrichment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	ctx := t.Context()

	var namespaceID, artifactID string
	is.NoErr(pool.QueryRow(ctx,
		`INSERT INTO namespace (name, visibility) VALUES ('orphan-ns', 'private') RETURNING id::text`,
	).Scan(&namespaceID))
	is.NoErr(pool.QueryRow(ctx,
		`INSERT INTO artifact (type, name) VALUES ('container', 'orphan/img') RETURNING id::text`,
	).Scan(&artifactID))
	const rawBom = `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"container","name":"orphan/img",
		"properties":[{"name":"syft:image:labels:org.opencontainers.image.architecture","value":"arm64"}]}}}`
	newSBOM := func() string {
		var id string
		is.NoErr(pool.QueryRow(ctx,
			`INSERT INTO sbom (artifact_id, namespace_id, spec_version, version, raw_bom)
			 VALUES ($1, $2, '1.6', 1, $3::jsonb) RETURNING id::text`,
			artifactID, namespaceID, rawBom).Scan(&id))
		return id
	}
	orphan, partial, legacy, enqueued := newSBOM(), newSBOM(), newSBOM(), newSBOM()
	exec := func(sql string, args ...any) {
		_, err := pool.Exec(ctx, sql, args...)
		is.NoErr(err)
	}
	exec(`INSERT INTO enrichment_jobs (sbom_id, enricher_name) VALUES ($1, 'user')`, partial)
	for _, name := range names.Roots() {
		exec(`INSERT INTO enrichment (sbom_id, enricher_name, status) VALUES ($1, $2, 'success')`, legacy, name)
		exec(`INSERT INTO enrichment_jobs (sbom_id, enricher_name) VALUES ($1, $2)`, enqueued, name)
	}

	res, err := service.Backfill(ctx, repository.New(pool), service.BackfillBatches{SBOMs: 1, Components: 10})
	is.NoErr(err)
	is.Equal(res.RootEnrichment, service.BackfillCounts{Updated: 2})

	jobs := func(sbomID string) int {
		var n int
		is.NoErr(pool.QueryRow(ctx, `SELECT count(*) FROM enrichment_jobs WHERE sbom_id = $1`, sbomID).Scan(&n))
		return n
	}
	is.Equal(jobs(orphan), len(names.Roots()))
	is.Equal(jobs(partial), len(names.Roots()))
	is.Equal(jobs(legacy), 0)
	is.Equal(jobs(enqueued), len(names.Roots()))
	var arch string
	is.NoErr(pool.QueryRow(ctx,
		`SELECT architecture FROM enrichment_jobs WHERE sbom_id = $1 AND enricher_name = 'oci-metadata'`, orphan).Scan(&arch))
	is.Equal(arch, "arm64")

	again, err := service.Backfill(ctx, repository.New(pool), service.BackfillBatches{SBOMs: 1, Components: 10})
	is.NoErr(err)
	is.Equal(again.RootEnrichment, service.BackfillCounts{})
}
