package scanner

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/pfenerty/ocidex/internal/metrics"
	"github.com/pfenerty/ocidex/internal/service"
)

// LastWalkLister returns each registry's latest walk stats keyed by registry
// ID; service.RegistryService satisfies it.
type LastWalkLister interface {
	LastWalks(ctx context.Context) (map[string]service.WalkStats, error)
}

// walkStatsCacheTTL bounds how often the gauges read the registry table:
// scrapes inside it reuse the last read. Walks run minutes apart, so a few
// seconds of staleness changes nothing.
const walkStatsCacheTTL = 30 * time.Second

// ObserveWalkStats reports every registry's last walk window (ADR-0053 S7,
// ADR-0054 M5): ocidex.registry.tags.selected and
// ocidex.registry.tags.skipped_limit, labelled by registry ID. Values come from
// the stats each walk stores, so they always match the API's last_walk, and a
// deleted registry stops being reported. Walks run in scanner-worker, so the
// API reports them; with several API replicas each reports the same values.
func ObserveWalkStats(mp metric.MeterProvider, lister LastWalkLister, logger *slog.Logger) (metric.Registration, error) {
	m := metrics.Meter(mp)
	selected, err := m.Int64ObservableGauge("ocidex.registry.tags.selected",
		metric.WithDescription("Tags inside the registry's selection window at its last walk."),
		metric.WithUnit("{tag}"))
	if err != nil {
		return nil, err
	}
	skipped, err := m.Int64ObservableGauge("ocidex.registry.tags.skipped_limit",
		metric.WithDescription("Matching tags left out by tag_limit at the registry's last walk."),
		metric.WithUnit("{tag}"))
	if err != nil {
		return nil, err
	}

	var (
		mu     sync.Mutex
		last   map[string]service.WalkStats
		lastAt time.Time
	)
	return m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		mu.Lock()
		defer mu.Unlock()
		if last == nil || time.Since(lastAt) >= walkStatsCacheTTL {
			walks, err := lister.LastWalks(ctx)
			if err != nil {
				logger.Warn("registry walk metrics: listing last walks", "err", err)
				return nil
			}
			last, lastAt = walks, time.Now()
		}
		for id, w := range last {
			if w.Error != "" {
				continue // a failed walk selected nothing; reporting 0 would read as an empty window
			}
			reg := metric.WithAttributes(attribute.String("registry", id))
			o.ObserveInt64(selected, int64(w.Selected), reg)
			o.ObserveInt64(skipped, int64(w.SkippedByLimit), reg)
		}
		return nil
	}, selected, skipped)
}
