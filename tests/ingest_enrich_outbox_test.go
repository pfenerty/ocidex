package tests

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/enrichment/names"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/service"
)

// cancellingPublisher cancels the ingest's request context when the post-commit
// event fires, as a client that disconnects right after commit would, and
// records whether the context it was handed was already dead.
type cancellingPublisher struct {
	cancel     context.CancelFunc
	ctxAlive   bool
	publishedN int
}

func (p *cancellingPublisher) Publish(ctx context.Context, _ event.Type, _ any) {
	p.cancel()
	p.publishedN++
	p.ctxAlive = ctx.Err() == nil
}

// TestIngestCommitsRootEnrichmentJobs covers ocidex-n1z4.1: the root
// enrichers' jobs commit with the SBOM, so a request context cancelled right
// after commit still leaves one enrichment_jobs row per root enricher, and the
// post-commit event is not cut short by it.
func TestIngestCommitsRootEnrichmentJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	is := is.New(t)
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	owner := seedUser(t, pool, 5170, "enrich-outbox", "member")
	ns := seedNamespace(t, pool, "enrich-outbox", owner, "public")
	var source pgtype.UUID
	is.NoErr(source.Scan(seedSource(t, pool, ns, "upload", "ci")))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pub := &cancellingPublisher{cancel: cancel}
	svc := service.NewSBOMService(pool, pub, nil)

	bom, raw := licenseOrderSBOM(t, 9100, []string{"MIT"})
	id, err := svc.Ingest(ctx, bom, raw, service.IngestParams{
		SourceID: source, Architecture: "amd64", BuildDate: "2026-01-01T00:00:00Z",
	})
	is.NoErr(err)
	is.Equal(pub.publishedN, 1)
	is.True(pub.ctxAlive) // the post-commit event runs detached from the request

	rows, err := pool.Query(t.Context(),
		`SELECT enricher_name FROM enrichment_jobs WHERE sbom_id = $1 ORDER BY enricher_name`, id)
	is.NoErr(err)
	var got []string
	for rows.Next() {
		var n string
		is.NoErr(rows.Scan(&n))
		got = append(got, n)
	}
	is.NoErr(rows.Err())
	want := []string{names.OCIMetadata, names.Provenance, names.User} // sorted
	is.Equal(got, want)
}
