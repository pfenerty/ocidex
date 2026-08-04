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
// exist without a session.
//
// These cover every viewer except one who owns a private registry — see
// statsScopeKey, which collapses viewers with no private registry of their own
// onto the anonymous scope, because they see exactly the public set. Scopes
// that remain per-user are unbounded and cannot be enumerated, so they are
// served stale-or-empty rather than computed on the request path.
func warmedScopes() []VisibilityFilter {
	return []VisibilityFilter{
		{},              // anonymous — public registries only
		{IsAdmin: true}, // admin — everything
	}
}

// Run warms once immediately, then waits interval *after each pass finishes*
// before starting the next, until ctx is cancelled.
//
// The interval is a gap between passes, not a period. A ticker would fire again
// while the previous pass was still running whenever a pass outlasts the
// interval — which is exactly what happened in production, where a pass took
// ~5.6 minutes against a 5 minute period. Passes then overlapped without bound
// and permanently consumed the connection pool, so ordinary requests queued for
// a connection until they hit the 30s HTTP timeout.
func (w *StatsWarmer) Run(ctx context.Context) {
	timer := time.NewTimer(w.interval)
	defer timer.Stop()

	for {
		w.tick(ctx)

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(w.interval)

		select {
		case <-timer.C:
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
