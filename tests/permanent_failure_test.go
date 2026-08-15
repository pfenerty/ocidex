package tests

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// jobRowState reads back the fields the fail query writes, for either queue.
func jobRowState(t *testing.T, pool *pgxpool.Pool, table, id string) (state string, attempts int32, lastError *string, finished *time.Time) {
	t.Helper()
	// #nosec G201 -- table is a test-local literal, never user input.
	q := `SELECT state, attempts, last_error, finished_at FROM ` + table + ` WHERE id = $1::uuid`
	if err := pool.QueryRow(t.Context(), q, id).Scan(&state, &attempts, &lastError, &finished); err != nil {
		t.Fatalf("reading %s row: %v", table, err)
	}
	return state, attempts, lastError, finished
}

// TestFailOrRequeue_PermanentBudget pins the SQL semantics that
// jobqueue.Permanent relies on (ocidex-9eu4): because the claim query
// increments attempts *before* the processor runs, passing maxAttempts=0 to the
// unchanged FailOrRequeue query makes `attempts >= max_attempts` true on the
// first attempt, so the row goes straight to 'failed' with finished_at set.
// Nothing in the Go unit tests can prove this — it lives entirely in the query.
func TestFailOrRequeue_PermanentBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	ctx := t.Context()
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	jobSvc := service.NewJobService(pool)

	enqueueClaimed := func(digest string) string {
		t.Helper()
		job, err := jobSvc.Enqueue(ctx, "", "repo/permanent", digest, "", "latest", "")
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		claim, ok, err := jobSvc.ClaimByID(ctx, job.ID, "test-worker")
		if err != nil || !ok {
			t.Fatalf("claim: ok=%v err=%v", ok, err)
		}
		// The premise of the whole mechanism: attempts is already 1 here.
		if claim.Attempts != 1 {
			t.Fatalf("attempts after first claim = %d, want 1", claim.Attempts)
		}
		return job.ID
	}

	t.Run("permanent fails on first attempt", func(t *testing.T) {
		is := is.New(t)

		id := enqueueClaimed("sha256:1111111111111111111111111111111111111111111111111111111111111111")

		state, err := jobSvc.FailOrRequeue(ctx, id, "permanent: scan: unsupported layer media type", 0)
		is.NoErr(err)
		is.Equal(state, "failed")

		gotState, attempts, lastError, finished := jobRowState(t, pool, "scan_jobs", id)
		is.Equal(gotState, "failed")
		is.Equal(attempts, int32(1))
		is.True(finished != nil)
		is.True(lastError != nil)
		is.Equal(*lastError, "permanent: scan: unsupported layer media type")
	})

	t.Run("transient requeues with budget left", func(t *testing.T) {
		is := is.New(t)

		id := enqueueClaimed("sha256:2222222222222222222222222222222222222222222222222222222222222222")

		state, err := jobSvc.FailOrRequeue(ctx, id, "connection refused", 3)
		is.NoErr(err)
		is.Equal(state, "queued")

		gotState, attempts, _, finished := jobRowState(t, pool, "scan_jobs", id)
		is.Equal(gotState, "queued")
		is.Equal(attempts, int32(1))
		is.True(finished == nil)
	})
}

// TestFailOrRequeue_PermanentBudgetEnrichment mirrors the scan assertion against
// enrichment_jobs. The two queries are structurally identical today; the shared
// jobqueue mechanism silently depends on them staying that way, so both are
// pinned rather than just the one the scanner uses.
func TestFailOrRequeue_PermanentBudgetEnrichment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	ctx := t.Context()
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	sbomID := ingestChainSBOM(t, pool)
	enrichJobSvc := service.NewEnrichJobService(pool, "git")

	is := is.New(t)
	is.NoErr(enrichJobSvc.Enqueue(ctx, sbomID, "amd64", "2026-01-01T00:00:00Z", "git"))

	id := enrichmentJobID(ctx, t, pool, sbomID, "git")

	claim, ok, err := enrichJobSvc.ClaimByID(ctx, id, "test-worker")
	is.NoErr(err)
	is.True(ok)
	is.Equal(claim.Attempts, int32(1))

	state, err := enrichJobSvc.FailOrRequeue(ctx, id, "permanent: boom", 0)
	is.NoErr(err)
	is.Equal(state, "failed")

	gotState, attempts, lastError, finished := jobRowState(t, pool, "enrichment_jobs", id)
	is.Equal(gotState, "failed")
	is.Equal(attempts, int32(1))
	is.True(finished != nil)
	is.True(lastError != nil)
	is.Equal(*lastError, "permanent: boom")
}

// enrichmentJobID resolves the row Enqueue just wrote; Enqueue returns only an
// error, so the id has to come back out of the table.
func enrichmentJobID(ctx context.Context, t *testing.T, pool *pgxpool.Pool, sbomID pgtype.UUID, enricher string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx,
		`SELECT id::text FROM enrichment_jobs WHERE sbom_id = $1 AND enricher_name = $2`,
		sbomID, enricher,
	).Scan(&id)
	if err != nil {
		t.Fatalf("resolving enrichment job id: %v", err)
	}
	return id
}
