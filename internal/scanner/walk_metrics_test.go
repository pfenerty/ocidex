package scanner

import (
	"context"
	"testing"

	"github.com/matryer/is"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/pfenerty/ocidex/internal/service"
)

type fakeLastWalks struct {
	walks map[string]service.WalkStats
	calls int
}

func (f *fakeLastWalks) LastWalks(context.Context) (map[string]service.WalkStats, error) {
	f.calls++
	return f.walks, nil
}

func gaugeValues(t *testing.T, reader *sdkmetric.ManualReader) map[string]map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out[m.Name] = map[string]int64{}
			for _, dp := range m.Data.(metricdata.Gauge[int64]).DataPoints {
				reg, _ := dp.Attributes.Value(attribute.Key("registry"))
				out[m.Name][reg.AsString()] = dp.Value
			}
		}
	}
	return out
}

// TestObserveWalkStats covers ocidex-5y0r.7: the gauges carry each registry's
// stored last walk, skip a failed walk and a never-walked registry, and reuse
// one read within the cache window.
func TestObserveWalkStats(t *testing.T) {
	is := is.New(t)
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	lister := &fakeLastWalks{walks: map[string]service.WalkStats{
		"r1": {Selected: 50, SkippedByLimit: 185, Queued: 3},
		"r2": {Selected: 5},
		"r3": {Error: "listing catalog: 401"},
	}}
	_, err := ObserveWalkStats(mp, lister, discardLogger())
	is.NoErr(err)

	got := gaugeValues(t, reader)
	is.Equal(got["ocidex.registry.tags.selected"], map[string]int64{"r1": 50, "r2": 5})
	is.Equal(got["ocidex.registry.tags.skipped_limit"], map[string]int64{"r1": 185, "r2": 0})

	gaugeValues(t, reader)
	is.Equal(lister.calls, 1) // cached within walkStatsCacheTTL
}
