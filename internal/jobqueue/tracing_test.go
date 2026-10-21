package jobqueue

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/matryer/is"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/pfenerty/ocidex/internal/tracing"
)

type tracedClaim struct {
	testClaim
	traceContext string
}

func (c tracedClaim) JobTraceContext() string { return c.traceContext }

// onceQueue hands out its claim once, by ID or by poll, then reports empty.
type onceQueue struct {
	claim tracedClaim
	given bool
}

func (q *onceQueue) take() (tracedClaim, bool, error) {
	if q.given {
		return tracedClaim{}, false, nil
	}
	q.given = true
	return q.claim, true, nil
}

func (q *onceQueue) ClaimByID(context.Context, string, string) (tracedClaim, bool, error) {
	return q.take()
}
func (q *onceQueue) ClaimNext(context.Context, string) (tracedClaim, bool, error) { return q.take() }
func (q *onceQueue) FailOrRequeue(context.Context, string, string, int32) (string, error) {
	return "queued", nil
}
func (q *onceQueue) RequeueStuckRunning(context.Context, time.Duration, int32) error { return nil }

// TestJobSpanParentedOnRow covers ADR-0055 T3: whether a worker claims the row
// from a hint or from its poll loop, the job span is a child of the context
// stored on the row, and the processor runs inside that span.
func TestJobSpanParentedOnRow(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	parentCtx, parent := tp.Tracer("test").Start(context.Background(), "upload")
	stored := tracing.Inject(parentCtx)
	parent.End()

	paths := map[string]func(*Worker[tracedClaim]){
		"hint": func(w *Worker[tracedClaim]) { w.processByID(context.Background(), "job-1") },
		"poll": func(w *Worker[tracedClaim]) { w.drainPoll(context.Background()) },
	}
	for name, claimVia := range paths {
		t.Run(name, func(t *testing.T) {
			is := is.New(t)
			exp.Reset()
			var inProcessor trace.SpanContext
			q := &onceQueue{claim: tracedClaim{testClaim{id: "job-1", attempts: 2}, stored}}
			processor := func(ctx context.Context, _ tracedClaim) error {
				inProcessor = trace.SpanContextFromContext(ctx)
				return errors.New("transient")
			}
			w := NewWorker("test", nil, "TEST", Queue[tracedClaim](q), processor,
				Config{MaxAttempts: 3, JobTimeout: time.Second}, slog.New(slog.NewTextHandler(io.Discard, nil))).
				WithTracing(tp, "scan job")

			claimVia(w)

			spans := exp.GetSpans()
			is.Equal(len(spans), 1)
			s := spans[0]
			is.Equal(s.Name, "scan job")
			is.Equal(s.SpanKind, trace.SpanKindConsumer)
			is.Equal(s.Parent.TraceID(), parent.SpanContext().TraceID()) // joins the upload's trace
			is.Equal(s.Parent.SpanID(), parent.SpanContext().SpanID())
			is.Equal(inProcessor.SpanID(), s.SpanContext.SpanID()) // the processor runs in the job span
			is.Equal(s.Status.Code, codes.Error)
		})
	}
}

func TestJobSpanWithoutStoredContextStartsATrace(t *testing.T) {
	is := is.New(t)
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	q := &onceQueue{claim: tracedClaim{testClaim{id: "job-1", attempts: 1}, ""}}
	w := NewWorker("test", nil, "TEST", Queue[tracedClaim](q), func(context.Context, tracedClaim) error { return nil },
		Config{MaxAttempts: 3, JobTimeout: time.Second}, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithTracing(tp, "enrich oci-metadata")
	w.drainPoll(context.Background())

	spans := exp.GetSpans()
	is.Equal(len(spans), 1)
	is.True(!spans[0].Parent.IsValid()) // a row queued with tracing off: the job is its own root
}
