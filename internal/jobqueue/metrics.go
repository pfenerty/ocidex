package jobqueue

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"

	"github.com/pfenerty/ocidex/internal/metrics"
	"github.com/pfenerty/ocidex/internal/tracing"
)

// Job outcomes for ocidex.jobs.processed (ADR-0054 M5).
const (
	outcomeSuccess          = "success"
	outcomeRetry            = "retry"
	outcomePermanentFailure = "permanent_failure"
)

// DepthCounter is implemented by a Queue that can count its own rows. When the
// Worker's queue implements it, WithMetrics also reports the ocidex.jobs
// gauge. CountActive returns queued and running counts keyed by state.
type DepthCounter interface {
	CountActive(ctx context.Context) (map[string]int64, error)
}

// activeStates are the states the depth gauge always reports, as 0 when empty,
// so a drained queue reads 0 instead of the series disappearing.
var activeStates = []string{"queued", "running"}

// depthCacheTTL bounds how often the gauge queries the database: concurrent or
// back-to-back scrapes within it reuse the last count.
const depthCacheTTL = 5 * time.Second

type workerMetrics struct {
	queue     attribute.KeyValue
	processed metric.Int64Counter
	duration  metric.Float64Histogram
	depth     metric.Registration // nil when the queue is not a DepthCounter
}

func noopWorkerMetrics() workerMetrics {
	m := noop.NewMeterProvider().Meter("")
	processed, _ := m.Int64Counter("")
	duration, _ := m.Float64Histogram("")
	return workerMetrics{processed: processed, duration: duration}
}

// TraceCarrier is implemented by a Claim that carries the trace context of
// whatever queued it (ADR-0055 T3). The job's span is then that trace's child,
// whichever path claimed the row.
type TraceCarrier interface {
	JobTraceContext() string
}

// WithTracing starts a consumer span named spanName ("scan job", "enrich
// oci-metadata") around each job on tp. Call it before Start.
func (w *Worker[C]) WithTracing(tp trace.TracerProvider, spanName string) *Worker[C] {
	w.tracer = tracing.Tracer(tp)
	w.spanName = spanName
	return w
}

// startJobSpan parents the job's span on the claim's stored context and returns
// the context the processor runs in, so its queries, publishes and any jobs it
// queues join the same trace.
func (w *Worker[C]) startJobSpan(ctx context.Context, claim C) (context.Context, trace.Span) {
	if tc, ok := any(claim).(TraceCarrier); ok {
		ctx = tracing.Extract(ctx, tc.JobTraceContext())
	}
	attrs := []attribute.KeyValue{
		attribute.String("ocidex.job.id", claim.JobID()),
		attribute.Int("ocidex.job.attempt", int(claim.JobAttempts())),
	}
	if w.metrics.queue.Valid() {
		attrs = append(attrs, w.metrics.queue)
	}
	return w.tracer.Start(ctx, w.spanName, trace.WithSpanKind(trace.SpanKindConsumer), trace.WithAttributes(attrs...))
}

// WithMetrics records the worker's jobs on mp under the given queue label: scan,
// or the enricher name (ADR-033). Call it before Start.
func (w *Worker[C]) WithMetrics(mp metric.MeterProvider, queue string) *Worker[C] {
	meter := metrics.Meter(mp)
	processed, err := meter.Int64Counter("ocidex.jobs.processed",
		metric.WithDescription("Jobs a worker finished processing, by outcome."),
		metric.WithUnit("{job}"))
	if err != nil {
		w.logger.Error(w.name+": job metrics disabled", "err", err)
		return w
	}
	duration, err := meter.Float64Histogram("ocidex.job.duration",
		metric.WithDescription("Time a worker spent processing one job."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(metrics.DurationBuckets...))
	if err != nil {
		w.logger.Error(w.name+": job metrics disabled", "err", err)
		return w
	}
	wm := workerMetrics{queue: attribute.String("queue", queue), processed: processed, duration: duration}

	if dc, ok := w.queue.(DepthCounter); ok {
		reg, err := registerDepth(meter, dc, wm.queue, w)
		if err != nil {
			w.logger.Error(w.name+": queue depth metric disabled", "err", err)
		}
		wm.depth = reg
	}
	w.metrics = wm
	return w
}

func registerDepth[C Claim](meter metric.Meter, dc DepthCounter, queue attribute.KeyValue, w *Worker[C]) (metric.Registration, error) {
	gauge, err := meter.Int64ObservableGauge("ocidex.jobs",
		metric.WithDescription("Jobs in the queue, by state (queued and running)."),
		metric.WithUnit("{job}"))
	if err != nil {
		return nil, err
	}
	var (
		mu     sync.Mutex
		last   map[string]int64
		lastAt time.Time
	)
	return meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		mu.Lock()
		defer mu.Unlock()
		if last == nil || time.Since(lastAt) >= depthCacheTTL {
			counts, err := dc.CountActive(ctx)
			if err != nil {
				w.logger.Warn(w.name+": count queue depth", "err", err)
				return nil
			}
			last, lastAt = counts, time.Now()
		}
		for _, state := range activeStates {
			o.ObserveInt64(gauge, last[state], metric.WithAttributes(queue, attribute.String("state", state)))
		}
		return nil
	}, gauge)
}

func (m workerMetrics) record(ctx context.Context, outcome string, elapsed time.Duration) {
	m.processed.Add(ctx, 1, metric.WithAttributes(m.queue, attribute.String("outcome", outcome)))
	m.duration.Record(ctx, elapsed.Seconds(), metric.WithAttributes(m.queue))
}

func (m workerMetrics) stop() {
	if m.depth != nil {
		_ = m.depth.Unregister()
	}
}
