package metrics_test

import (
	"context"
	"testing"
	"time"

	"github.com/matryer/is"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/pfenerty/ocidex/internal/metrics"
)

func TestObservePool(t *testing.T) {
	is := is.New(t)
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	stats := metrics.PoolStats{
		Acquired: 3, Idle: 2, Total: 5, Max: 10,
		AcquireCount: 100, EmptyAcquireCount: 15, CanceledAcquireCount: 4,
		EmptyAcquireWait: 1500 * time.Millisecond,
	}
	_, err := metrics.ObservePool(mp, metrics.PoolBackground, func() metrics.PoolStats { return stats })
	is.NoErr(err)

	var rm metricdata.ResourceMetrics
	is.NoErr(reader.Collect(context.Background(), &rm))
	got := map[string]float64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch d := m.Data.(type) {
			case metricdata.Gauge[int64]:
				for _, dp := range d.DataPoints {
					got[m.Name+" "+value(dp.Attributes, "state")] = float64(dp.Value)
					is.Equal(value(dp.Attributes, "pool"), "background")
				}
			case metricdata.Sum[int64]:
				is.True(d.IsMonotonic)
				for _, dp := range d.DataPoints {
					got[m.Name+" "+value(dp.Attributes, "outcome")] = float64(dp.Value)
				}
			case metricdata.Sum[float64]:
				is.Equal(m.Unit, "s")
				got[m.Name] = d.DataPoints[0].Value
			}
		}
	}
	is.Equal(got, map[string]float64{
		"ocidex.db.pool.connections acquired": 3,
		"ocidex.db.pool.connections idle":     2,
		"ocidex.db.pool.connections total":    5,
		"ocidex.db.pool.connections max":      10,
		"ocidex.db.pool.acquires waited":      15,
		"ocidex.db.pool.acquires immediate":   85, // successful acquires that found an idle connection
		"ocidex.db.pool.acquires canceled":    4,
		"ocidex.db.pool.acquire_wait":         1.5,
	})
}

func value(set attribute.Set, key string) string {
	v, _ := set.Value(attribute.Key(key))
	return v.AsString()
}
