package service

import (
	"context"
	"log/slog"
	"time"
)

// statsWarmTimeout bounds a single warm pass. It is deliberately far larger
// than any HTTP timeout: the whole point of warming out-of-band is that the
// aggregates are allowed to take as long as they take.
const statsWarmTimeout = 10 * time.Minute

// StatsWarmer keeps the dashboard-stats cache populated in the background.
//
// Without it the cache can only be filled by a request that survives long
// enough to compute the aggregates — and when they exceed the server's write
// timeout, every such request is cut off before it can write to the cache. The
// cache then never warms, so every subsequent load takes the slow path too: a
// self-perpetuating failure that shows the user an empty dashboard forever.
//
// The cache is per-process, so unlike the poller and reverifier this runs on
// every replica rather than behind leader election.
type StatsWarmer struct {
	svc      SearchService
	interval time.Duration
	logger   *slog.Logger
}

// NewStatsWarmer constructs a StatsWarmer. A non-positive interval falls back
// to StatsWarmInterval.
func NewStatsWarmer(svc SearchService, interval time.Duration, logger *slog.Logger) *StatsWarmer {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = StatsWarmInterval
	}
	return &StatsWarmer{svc: svc, interval: interval, logger: logger}
}

// warmedScopes are the visibility scopes the warmer refreshes: the two that
// exist without a session. Per-user scopes are unbounded and can't be
// enumerated, so they are still computed on demand.
func warmedScopes() []VisibilityFilter {
	return []VisibilityFilter{
		{},              // anonymous — public registries only
		{IsAdmin: true}, // admin — everything
	}
}

// Run warms once immediately, then every interval, until ctx is cancelled.
func (w *StatsWarmer) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.tick(ctx)
	for {
		select {
		case <-ticker.C:
			w.tick(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// tick recomputes each warmed scope in turn. Scopes run sequentially: they scan
// the same tables, so overlapping them would only make each one slower.
func (w *StatsWarmer) tick(ctx context.Context) {
	for _, vis := range warmedScopes() {
		if ctx.Err() != nil {
			return
		}
		w.warm(ctx, vis)
	}
}

func (w *StatsWarmer) warm(ctx context.Context, vis VisibilityFilter) {
	scopeCtx, cancel := context.WithTimeout(ctx, statsWarmTimeout)
	defer cancel()

	start := time.Now()
	// Log the cost even on success: this is the only place the true query time
	// is visible now that no request waits on it.
	if _, err := w.svc.WarmDashboardStats(scopeCtx, vis); err != nil {
		w.logger.Error("stats warm failed", "scope", statsCacheKey(vis), "duration", time.Since(start), "err", err)
		return
	}
	w.logger.Info("stats warmed", "scope", statsCacheKey(vis), "duration", time.Since(start))
}
