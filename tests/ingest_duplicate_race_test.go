package tests

import (
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// TestConcurrentDuplicateIngestIsIdempotent covers ocidex-n1z4.4: concurrent
// ingests of one digest all pass the existingByDigest pre-check, and the losers
// of the insert race must get the winner's id, not a unique-violation error.
func TestConcurrentDuplicateIngestIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	is := is.New(t)
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	owner := seedUser(t, pool, 5160, "dup-race", "member")
	ns := seedNamespace(t, pool, "dup-race", owner, "public")
	var source pgtype.UUID
	is.NoErr(source.Scan(seedSource(t, pool, ns, "upload", "ci")))
	svc := service.NewSBOMService(pool, nil, nil)

	const rounds, perRound = 5, 6
	for r := range rounds {
		var wg sync.WaitGroup
		ids := make(chan string, perRound)
		errs := make(chan error, perRound)
		for range perRound {
			// The same SBOM each time, decoded afresh: ingest may mutate it.
			bom, raw := licenseOrderSBOM(t, 9000+r, []string{"MIT"})
			wg.Go(func() {
				id, err := svc.Ingest(t.Context(), bom, raw, service.IngestParams{
					SourceID: source.String(), Architecture: "amd64", BuildDate: "2026-01-01T00:00:00Z",
				})
				if err != nil {
					errs <- err
					return
				}
				ids <- id
			})
		}
		wg.Wait()
		close(errs)
		close(ids)
		for err := range errs {
			t.Fatalf("round %d: concurrent duplicate ingest failed: %v", r, err)
		}
		var first string
		for id := range ids {
			if first == "" {
				first = id
			}
			is.Equal(id, first) // every ingest answers with the one stored SBOM
		}
	}
}
