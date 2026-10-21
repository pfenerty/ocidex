package tests

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/pfenerty/ocidex/internal/service"
	"github.com/pfenerty/ocidex/internal/tracing"
)

// TestScanJobTraceContext covers ocidex-v590.11 (ADR-0055 T3): Enqueue stores
// the caller's trace context, a claim returns it, a repeat enqueue of an active
// row keeps it, and re-queuing a finished row takes the new caller's.
func TestScanJobTraceContext(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	is := is.New(t)
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	jobSvc := service.NewJobService(pool, nil)
	tracer := sdktrace.NewTracerProvider().Tracer("test")
	traceOf := func(ctx context.Context) trace.TraceID { return trace.SpanContextFromContext(ctx).TraceID() }
	claimedTrace := func(c service.ScanJobClaim) trace.TraceID {
		return traceOf(tracing.Extract(context.Background(), c.TraceContext))
	}

	first, firstSpan := tracer.Start(t.Context(), "walk 1")
	defer firstSpan.End()
	job, err := jobSvc.Enqueue(first, "", "app", prunedTestDigest, "", "v1", "msg-trace", false)
	is.NoErr(err)

	second, secondSpan := tracer.Start(t.Context(), "walk 2")
	defer secondSpan.End()
	_, err = jobSvc.Enqueue(second, "", "app", prunedTestDigest, "", "v1", "msg-trace", false)
	is.NoErr(err)

	claim, ok, err := jobSvc.ClaimByID(t.Context(), job.ID, "worker-1")
	is.NoErr(err)
	is.True(ok)
	is.Equal(claimedTrace(claim), traceOf(first)) // the active row kept the trace that queued it

	is.NoErr(jobSvc.FinishByID(t.Context(), job.ID, pgtype.UUID{})) // sbom_id may be NULL
	_, err = jobSvc.Enqueue(second, "", "app", prunedTestDigest, "", "v1", "msg-trace", false)
	is.NoErr(err)
	claim, ok, err = jobSvc.ClaimNext(t.Context(), "worker-1")
	is.NoErr(err)
	is.True(ok)
	is.Equal(claimedTrace(claim), traceOf(second)) // a re-scan is a new run in the new trace

	// With tracing off nothing is stored, and the claim carries nothing.
	off, err := jobSvc.Enqueue(context.Background(), "", "app", prunedTestDigest, "", "v1", "msg-untraced", false)
	is.NoErr(err)
	claim, ok, err = jobSvc.ClaimByID(t.Context(), off.ID, "worker-1")
	is.NoErr(err)
	is.True(ok)
	is.Equal(claim.TraceContext, "")
}
