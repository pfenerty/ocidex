package service

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/metrics"
)

// RetentionLockName is hashed into the advisory lock key that leader-elects the
// retention sweep across API replicas (ADR-0056 R6).
const RetentionLockName = "ocidex-retention"

// retentionBatchPause is the gap between two delete batches, so a long sweep
// leaves the database room for everything else.
const retentionBatchPause = 2 * time.Second

// retentionSweepBuckets are the sweep duration histogram's boundaries, in
// seconds. A sweep that prunes a backlog runs for minutes, far past the shared
// request-sized buckets.
var retentionSweepBuckets = []float64{1, 10, 60, 300, 900, 1800, 3600, 7200}

// RetentionSweeper runs retention sweeps on an interval. Run it under
// LeaderElect so only one replica sweeps.
type RetentionSweeper struct {
	svc       RetentionService
	policy    RetentionPolicy
	dryRun    bool
	interval  time.Duration
	batch     int
	pause     time.Duration
	publisher event.Publisher
	logger    *slog.Logger

	pruned   metric.Int64Counter     // nil until WithMetrics
	duration metric.Float64Histogram // nil until WithMetrics
}

// NewRetentionSweeper constructs a sweeper. dryRun reports what each sweep
// would delete and deletes nothing.
func NewRetentionSweeper(svc RetentionService, policy RetentionPolicy, dryRun bool, interval time.Duration, batch int, logger *slog.Logger) *RetentionSweeper {
	if logger == nil {
		logger = slog.Default()
	}
	return &RetentionSweeper{
		svc: svc, policy: policy, dryRun: dryRun, interval: interval, batch: batch,
		pause: retentionBatchPause, logger: logger,
	}
}

// WithPublisher publishes one retention.swept event per sweep, which the audit
// extension records.
func (s *RetentionSweeper) WithPublisher(p event.Publisher) *RetentionSweeper {
	s.publisher = p
	return s
}

// WithMetrics records ocidex.retention.pruned (by class) and
// ocidex.retention.sweep.duration on mp. A dry run counts nothing as pruned.
func (s *RetentionSweeper) WithMetrics(mp metric.MeterProvider) *RetentionSweeper {
	meter := metrics.Meter(mp)
	pruned, err := meter.Int64Counter("ocidex.retention.pruned",
		metric.WithDescription("SBOMs the retention sweep deleted, by class (ADR-0056)."),
		metric.WithUnit("{sbom}"))
	if err != nil {
		s.logger.Error("retention metrics disabled", "err", err)
		return s
	}
	duration, err := meter.Float64Histogram("ocidex.retention.sweep.duration",
		metric.WithDescription("Time one retention sweep took."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(retentionSweepBuckets...))
	if err != nil {
		s.logger.Error("retention metrics disabled", "err", err)
		return s
	}
	s.pruned, s.duration = pruned, duration
	return s
}

// Run sweeps once immediately, then once per interval until ctx is cancelled.
// The wait follows each sweep, so a sweep that outlasts the interval never
// overlaps the next.
func (s *RetentionSweeper) Run(ctx context.Context) {
	for {
		if _, err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
			s.logger.Error("retention sweep failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.interval):
		}
	}
}

// Sweep runs one sweep: in dry-run it counts the candidates, otherwise it
// deletes batch after batch until none are left or ctx is cancelled. It
// returns the counts per class, deleted or (in dry-run) deletable.
func (s *RetentionSweeper) Sweep(ctx context.Context) (PruneCounts, error) {
	start := time.Now()
	var (
		total PruneCounts
		err   error
	)
	if s.dryRun {
		total, err = s.count(ctx)
	} else {
		total, err = s.prune(ctx)
	}
	elapsed := time.Since(start)
	if s.duration != nil {
		s.duration.Record(ctx, elapsed.Seconds())
	}
	s.logger.Info("retention sweep",
		"dry_run", s.dryRun, "window", total.Window, "newest", total.Newest,
		"duration", elapsed, "complete", err == nil)
	if s.publisher != nil {
		s.publisher.Publish(ctx, event.RetentionSwept, event.RetentionSweptData{
			DryRun: s.dryRun, Window: total.Window, Newest: total.Newest,
		})
	}
	return total, err
}

func (s *RetentionSweeper) count(ctx context.Context) (PruneCounts, error) {
	c, err := s.svc.Candidates(ctx, s.policy, 0)
	if err != nil {
		return PruneCounts{}, err
	}
	return PruneCounts{Window: int64(len(c.Window)), Newest: int64(len(c.Newest))}, nil
}

func (s *RetentionSweeper) prune(ctx context.Context) (PruneCounts, error) {
	var total PruneCounts
	for {
		n, err := s.svc.Prune(ctx, s.policy, s.batch)
		total.Window += n.Window
		total.Newest += n.Newest
		s.recordPruned(ctx, n)
		if err != nil {
			return total, err
		}
		if n.Total() == 0 {
			return total, nil
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(s.pause):
		}
	}
}

func (s *RetentionSweeper) recordPruned(ctx context.Context, n PruneCounts) {
	if s.pruned == nil {
		return
	}
	if n.Window > 0 {
		s.pruned.Add(ctx, n.Window, metric.WithAttributes(attribute.String("class", "window")))
	}
	if n.Newest > 0 {
		s.pruned.Add(ctx, n.Newest, metric.WithAttributes(attribute.String("class", "newest")))
	}
}
