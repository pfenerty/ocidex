package service

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"

	"github.com/pfenerty/ocidex/internal/repository"
)

// RollupRefreshInterval is the gap between rollup refresh passes.
//
// The rollups only change when SBOMs are ingested, and a stale entry costs
// nothing worse than a list page that omits a package ingested in the last few
// minutes. The pass itself is expensive — it is the same set of aggregates that
// made the list pages time out when they ran per request — so it is spaced well
// apart rather than chased close to real time.
const RollupRefreshInterval = 15 * time.Minute

// RollupPollInterval is how often the refresher checks whether new SBOMs have
// landed since the last pass.
//
// The check is a count and a max over sbom, not a rebuild, so it can run at this
// cadence without cost. It exists because RollupRefreshInterval alone would mean
// an SBOM pushed a minute after a pass stayed invisible on the Components page
// for a quarter of an hour — an unacceptable answer to "I just uploaded this,
// where is it?".
const RollupPollInterval = 30 * time.Second

// rollupMinGap is the floor on the interval between two passes, however fast
// SBOMs arrive.
//
// During a registry scan the watermark moves continuously, so without a floor
// the refresher would rebuild back to back forever and permanently occupy the
// two-connection background pool — reintroducing, in a new place, exactly the
// starvation the stats warmer used to cause.
const rollupMinGap = 2 * time.Minute

// rollupRefreshTimeout bounds a single pass. Like the stats warmer, this is far
// larger than any HTTP timeout: the point of doing this out of band is that the
// aggregates are allowed to take as long as they take.
const rollupRefreshTimeout = 20 * time.Minute

// rollupSwapLockTimeout bounds how long the swap waits for its lock on each
// rollup table.
//
// The swap DELETEs, so it takes ROW EXCLUSIVE and readers never block it. What
// can is an ACCESS EXCLUSIVE holder — a migration's ALTER, a manual VACUUM
// FULL — and a pass queued behind one would hold its earlier tables' row locks
// for as long as that took. Failing the pass is strictly better: the previous
// snapshot stays live and the next pass retries.
const rollupSwapLockTimeout = 5 * time.Second

// RollupRefresher rebuilds the component/license/vulnerability rollup tables in
// the background.
//
// The list pages read these rollups instead of aggregating the component table
// per request, which is what made them exceed the HTTP timeout. Something has
// to keep them current, and it cannot be the request path.
//
// Unlike the stats warmer, whose cache is per-process, the rollups are shared
// database state, so a pass is single-flight across replicas via an advisory
// lock rather than leader-elected. Every replica attempts a pass; whichever
// wins the lock does the work and the rest return immediately.
type RollupRefresher struct {
	pool         dbPool
	interval     time.Duration
	pollInterval time.Duration
	minGap       time.Duration
	lockKey      int64
	logger       *slog.Logger

	// mu guards the gating state, which Run's goroutine and any RefreshNow
	// caller both write.
	mu       sync.Mutex
	lastPass time.Time
	lastMark repository.RollupWatermark
	haveMark bool

	// lastSuccess is when this replica last saw a pass commit (its own, or
	// another replica's that held the lock), seeded with Run's start so a
	// replica whose passes never succeed still warns. Only Run's goroutine
	// touches it.
	lastSuccess time.Time
}

// NewRollupRefresher constructs a RollupRefresher. A non-positive interval falls
// back to RollupRefreshInterval.
func NewRollupRefresher(pool dbPool, interval time.Duration, logger *slog.Logger) *RollupRefresher {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = RollupRefreshInterval
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(repository.RollupRefreshLockName))
	return &RollupRefresher{
		pool:         pool,
		interval:     interval,
		pollInterval: RollupPollInterval,
		minGap:       rollupMinGap,
		lockKey:      int64(h.Sum64()), //nolint:gosec // G115: an advisory lock key is an opaque 64-bit token
		logger:       logger,
	}
}

// LockKey returns the advisory lock key this refresher contends for. Exposed so
// startup can log it alongside the other background jobs' keys.
func (r *RollupRefresher) LockKey() int64 { return r.lockKey }

// Run refreshes once immediately, then polls until ctx is cancelled, running a
// pass whenever one is due.
//
// The wait is a gap after each poll rather than a fixed period: a ticker would
// keep firing while a pass was still running whenever a pass outlasts the
// interval, and overlapping passes on a two-connection pool would starve each
// other indefinitely.
func (r *RollupRefresher) Run(ctx context.Context) {
	timer := time.NewTimer(r.pollInterval)
	defer timer.Stop()
	r.lastSuccess = time.Now()

	for {
		r.tick(ctx)

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(r.pollInterval)

		select {
		case <-timer.C:
		case <-ctx.Done():
			return
		}
	}
}

// tick runs a pass if one is due, and does nothing otherwise. Most ticks do
// nothing: the poll interval is sized for latency after an ingest, not for how
// often a rebuild is warranted.
func (r *RollupRefresher) tick(ctx context.Context) {
	mark, markErr := repository.ReadRollupWatermark(ctx, r.pool)
	if markErr != nil {
		// A failed watermark read must not suppress the backstop, so fall
		// through to the time-based check with the watermark unknown.
		r.logger.Warn("reading rollup watermark", "err", markErr)
	}

	reason := r.dueReason(mark, markErr == nil)
	if reason == "" {
		return
	}

	passCtx, cancel := context.WithTimeout(ctx, rollupRefreshTimeout)
	defer cancel()

	start := time.Now()
	switch ran, err := r.refresh(passCtx); {
	case err != nil:
		r.logger.Error("rollup refresh failed", "reason", reason, "duration", time.Since(start), "err", err)
		// One failed pass is noise; a run of them means every list page that
		// reads a rollup is serving data that has stopped advancing, which is
		// otherwise invisible — the pages still render, just without whatever
		// was ingested since. Say so at a level someone will see.
		if time.Since(r.lastSuccess) > 2*r.interval {
			r.logger.Warn("rollups are stale", "last_success", r.lastSuccess, "age", time.Since(r.lastSuccess))
		}
	case !ran:
		// Another replica is doing the work, so its result will be visible to
		// this one. Record the pass to keep both replicas from spinning on a
		// watermark neither of them can clear.
		r.recordPass(mark, markErr == nil)
		r.lastSuccess = time.Now()
		r.logger.Debug("rollup refresh skipped", "reason", "another replica holds the lock")
	default:
		r.recordPass(mark, markErr == nil)
		r.lastSuccess = time.Now()
		// Log the cost even on success: this is the only place the true
		// aggregate time is visible now that no request waits on it.
		r.logger.Info("rollups refreshed", "reason", reason, "duration", time.Since(start))
	}
}

// dueReason reports why a pass should run now, or "" if none should.
//
// Two independent triggers. The watermark trigger keeps a freshly ingested SBOM
// from being invisible for a whole interval. The interval itself is the backstop
// for everything the watermark cannot see — chiefly vulnerability matches, which
// appear when the feed updates without any SBOM being ingested.
func (r *RollupRefresher) dueReason(mark repository.RollupWatermark, markOK bool) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.lastPass.IsZero() {
		return "startup"
	}
	since := time.Since(r.lastPass)
	switch {
	case since >= r.interval:
		return "backstop"
	case since < r.minGap:
		return ""
	case markOK && (!r.haveMark || mark != r.lastMark):
		return "ingest"
	default:
		return ""
	}
}

// recordPass marks a pass as having happened against the given watermark.
//
// The watermark stored is the one read *before* the pass started, not after, so
// an SBOM ingested while the aggregates were running still looks like new work
// on the next poll rather than being silently absorbed into a snapshot that
// predates it.
func (r *RollupRefresher) recordPass(mark repository.RollupWatermark, markOK bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastPass = time.Now()
	if markOK {
		r.lastMark, r.haveMark = mark, true
	}
}

// RefreshNow runs one pass immediately, bypassing the poll gating, and reports
// whether it ran — false means another replica held the lock.
//
// This exists for callers that need the rollups to reflect a write they have
// just made. Integration tests are the motivating case: without it, asserting
// that an ingested SBOM's components are searchable would mean sleeping for the
// poll interval.
func (r *RollupRefresher) RefreshNow(ctx context.Context) (bool, error) {
	mark, markErr := repository.ReadRollupWatermark(ctx, r.pool)

	ran, err := r.refresh(ctx)
	if err != nil {
		return false, err
	}
	r.recordPass(mark, markErr == nil)
	return ran, nil
}

// refresh runs one pass. It reports whether the pass actually ran: false means
// another replica held the lock, which is a normal outcome, not a failure.
//
// Everything happens in a single transaction so the three rollups are always
// mutually consistent — a reader can never see components from a new snapshot
// alongside vulnerabilities from the old one — and so the temp tables are
// dropped and the advisory lock released however the pass ends.
func (r *RollupRefresher) refresh(ctx context.Context) (bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("beginning rollup refresh: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	acquired, err := repository.TryLockRollupRefresh(ctx, tx, r.lockKey)
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}

	// The snapshots are built before any lock_timeout is set: they take minutes
	// and touch only temp tables, so there is nothing to time out on.
	if err := repository.BuildRollupSnapshots(ctx, tx); err != nil {
		return false, err
	}

	timeout := fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", rollupSwapLockTimeout.Milliseconds())
	if _, err := tx.Exec(ctx, timeout); err != nil {
		return false, fmt.Errorf("setting swap lock timeout: %w", err)
	}
	if err := repository.SwapRollupSnapshots(ctx, tx); err != nil {
		return false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("committing rollup refresh: %w", err)
	}
	return true, nil
}
