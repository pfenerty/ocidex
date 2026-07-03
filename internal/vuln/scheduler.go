package vuln

import (
	"context"
	"log/slog"
	"time"
)

// schedulerTick is how often the scheduler checks whether a refresh is due. The
// actual cadence between refreshes is governed by the configured interval; this
// short tick just lets a freshly elected leader pick up promptly.
const schedulerTick = time.Minute

// Scheduler runs a RefreshService on an interval. It is designed to be passed to
// service.LeaderElect so exactly one replica refreshes at a time; on each tick it
// gates on the persisted last-refresh time so a leader change does not re-run
// early. Run blocks until ctx is cancelled.
type Scheduler struct {
	svc      *RefreshService
	store    Store
	interval time.Duration
	logger   *slog.Logger
}

// NewScheduler constructs a Scheduler. interval is the minimum time between
// refreshes.
func NewScheduler(svc *RefreshService, store Store, interval time.Duration, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{svc: svc, store: store, interval: interval, logger: logger}
}

// Run ticks until ctx is cancelled, refreshing whenever the interval has elapsed
// since the last successful refresh. It also attempts one refresh immediately on
// startup if due.
func (s *Scheduler) Run(ctx context.Context) {
	s.runIfDue(ctx)
	ticker := time.NewTicker(schedulerTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runIfDue(ctx)
		}
	}
}

func (s *Scheduler) runIfDue(ctx context.Context) {
	due, err := s.due(ctx)
	if err != nil {
		s.logger.Error("vuln scheduler: checking due", "err", err)
		return
	}
	if !due {
		return
	}
	if err := s.svc.Refresh(ctx); err != nil {
		s.logger.Error("vuln scheduler: refresh failed", "err", err)
	}
}

func (s *Scheduler) due(ctx context.Context) (bool, error) {
	last, ok, err := s.store.LastRefreshedAt(ctx)
	if err != nil {
		return false, err
	}
	if !ok {
		return true, nil // never refreshed
	}
	return time.Since(last) >= s.interval, nil
}
