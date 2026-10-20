package jobqueue

import (
	"context"
	"errors"
	"testing"

	"github.com/matryer/is"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collect(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]metricdata.Metrics{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out[m.Name] = m
		}
	}
	return out
}

func attr(set attribute.Set, key string) string {
	v, _ := set.Value(attribute.Key(key))
	return v.AsString()
}

// TestRun_OutcomeMetrics covers ocidex-v590.3: each finished job counts once
// under its outcome, and an ordinary error counts as permanent_failure once the
// queue reports the row failed (budget spent), not only for Permanent errors.
func TestRun_OutcomeMetrics(t *testing.T) {
	is := is.New(t)
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	var next error
	q := &recordingQueue{}
	w := newTestWorker(q, func(context.Context, testClaim) error { return next }).WithMetrics(mp, "scan")

	for _, err := range []error{nil, nil, errors.New("timeout"), Permanent(errors.New("bad media type"))} {
		next = err
		w.run(t.Context(), testClaim{id: "job", attempts: 1})
	}
	exhausted := &exhaustedQueue{}
	w2 := newTestWorker(exhausted, func(context.Context, testClaim) error { return errors.New("timeout") }).WithMetrics(mp, "scan")
	w2.run(t.Context(), testClaim{id: "job", attempts: 3})

	got := collect(t, reader)
	counts := map[string]int64{}
	for _, dp := range got["ocidex.jobs.processed"].Data.(metricdata.Sum[int64]).DataPoints {
		is.Equal(attr(dp.Attributes, "queue"), "scan")
		counts[attr(dp.Attributes, "outcome")] = dp.Value
	}
	is.Equal(counts, map[string]int64{"success": 2, "retry": 1, "permanent_failure": 2})

	hist := got["ocidex.job.duration"].Data.(metricdata.Histogram[float64]).DataPoints
	is.Equal(len(hist), 1) // queue is the only attribute
	is.Equal(hist[0].Count, uint64(5))
	is.Equal(got["ocidex.job.duration"].Unit, "s")
}

// exhaustedQueue reports every failure as final, as FailOrRequeue does once
// attempts reach the budget.
type exhaustedQueue struct{ recordingQueue }

func (q *exhaustedQueue) FailOrRequeue(context.Context, string, string, int32) (string, error) {
	return "failed", nil
}

type depthQueue struct {
	recordingQueue
	calls  int
	counts map[string]int64
}

func (q *depthQueue) CountActive(context.Context) (map[string]int64, error) {
	q.calls++
	return q.counts, nil
}

func TestDepthGauge(t *testing.T) {
	is := is.New(t)
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	q := &depthQueue{counts: map[string]int64{"queued": 7}}
	w := newTestWorker(q, nil).WithMetrics(mp, "oci-metadata")

	got := collect(t, reader)
	states := map[string]int64{}
	for _, dp := range got["ocidex.jobs"].Data.(metricdata.Gauge[int64]).DataPoints {
		is.Equal(attr(dp.Attributes, "queue"), "oci-metadata")
		states[attr(dp.Attributes, "state")] = dp.Value
	}
	is.Equal(states, map[string]int64{"queued": 7, "running": 0}) // an empty state reads 0

	collect(t, reader)
	is.Equal(q.calls, 1) // a scrape inside the cache window reuses the count

	is.NoErr(w.Stop())
	got = collect(t, reader)
	_, still := got["ocidex.jobs"]
	is.True(!still) // Stop unregisters the callback
}
