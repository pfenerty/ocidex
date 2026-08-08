package enrichment

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment/names"
	"github.com/pfenerty/ocidex/internal/repository"
)

// recheckBatchSize caps how many SBOMs are requeued per tick, so a large
// backlog of due recheck candidates can't overwhelm the job queue at once.
//
// This bounds the *rate* of rechecks, not their period: the sweep only keeps
// up with the configured recheck interval while
// (interval / sweepInterval) * recheckBatchSize exceeds the number of
// provenance enrichments. Below that, the oldest-first sweep falls behind and
// the effective recheck period stretches out silently — tick() logs a warning
// when a full batch comes back, which is that signal.
const recheckBatchSize = 500

// sweepDivisor sets how many sweeps are scheduled per recheck interval, so the
// batch cap throttles throughput instead of stretching the period. See
// deriveSweepInterval.
const sweepDivisor = 24

// minSweepInterval floors the derived sweep cadence so a short recheck
// interval can't turn into a hot loop against the database.
const minSweepInterval = time.Minute

// RecheckStore is the subset of the repository needed to find and requeue
// provenance enrichments due for periodic re-verification.
type RecheckStore interface {
	ListSBOMsDueForProvenanceRecheck(ctx context.Context, arg repository.ListSBOMsDueForProvenanceRecheckParams) ([]pgtype.UUID, error)
	RequeueSucceededEnrichmentJob(ctx context.Context, arg repository.RequeueSucceededEnrichmentJobParams) (int64, error)
}

// Reverifier periodically requeues the provenance enrichment job for SBOMs
// whose last successful check is older than interval, so drift (a trust
// config change, or a registry deleting the artifact) gets detected even
// though nothing else re-triggers enrichment after initial ingest.
//
// interval is the staleness cutoff; sweepInterval is how often the sweep
// actually runs. They are deliberately distinct: sweeping several times per
// interval lets recheckBatchSize throttle the requeue rate without stretching
// the period over which every SBOM gets rechecked.
type Reverifier struct {
	store         RecheckStore
	interval      time.Duration
	sweepInterval time.Duration
	logger        *slog.Logger
}

// NewReverifier constructs a Reverifier. interval is how old a provenance
// enrichment's last check must be before it's requeued; the sweep cadence is
// derived from it by deriveSweepInterval.
func NewReverifier(store RecheckStore, interval time.Duration, logger *slog.Logger) *Reverifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reverifier{
		store:         store,
		interval:      interval,
		sweepInterval: deriveSweepInterval(interval),
		logger:        logger,
	}
}

// deriveSweepInterval spreads each recheck interval over sweepDivisor sweeps,
// so the per-tick batch cap bounds throughput rather than the recheck period.
// The result is floored at minSweepInterval to avoid hammering the database,
// and capped at interval so a short interval never sweeps less often than it
// asks for.
func deriveSweepInterval(interval time.Duration) time.Duration {
	sweep := interval / sweepDivisor
	if sweep < minSweepInterval {
		sweep = minSweepInterval
	}
	if sweep > interval {
		sweep = interval
	}
	return sweep
}

// Run ticks immediately on start, then at r.sweepInterval, requeuing due SBOMs
// on each tick. Blocks until ctx is cancelled.
func (r *Reverifier) Run(ctx context.Context) {
	ticker := time.NewTicker(r.sweepInterval)
	defer ticker.Stop()

	select {
	case <-ctx.Done():
		return
	default:
	}
	r.tick(ctx)

	for {
		select {
		case <-ticker.C:
			r.tick(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (r *Reverifier) tick(ctx context.Context) {
	due, err := r.store.ListSBOMsDueForProvenanceRecheck(ctx, repository.ListSBOMsDueForProvenanceRecheckParams{
		Cutoff:   pgtype.Timestamptz{Time: time.Now().Add(-r.interval), Valid: true},
		RowLimit: recheckBatchSize,
	})
	if err != nil {
		r.logger.Error("reverifier: listing SBOMs due for recheck", "err", err)
		return
	}
	requeued := 0
	for _, sbomID := range due {
		n, err := r.store.RequeueSucceededEnrichmentJob(ctx, repository.RequeueSucceededEnrichmentJobParams{
			SbomID:       sbomID,
			EnricherName: names.Provenance,
		})
		if err != nil {
			r.logger.Error("reverifier: requeuing provenance job", "sbom_id", sbomID, "err", err)
			continue
		}
		requeued += int(n)
	}
	if len(due) > 0 {
		r.logger.Info("reverifier: requeued provenance rechecks", "due", len(due), "requeued", requeued)
	}
	// A full batch means there were at least as many due SBOMs as the cap
	// allows, so the sweep may not be keeping pace with the recheck interval.
	// Left unlogged this is invisible until rechecks are days late.
	if len(due) >= recheckBatchSize {
		r.logger.Warn("reverifier: recheck batch hit the per-sweep cap; rechecks may be falling behind the configured interval",
			"batch_size", recheckBatchSize,
			"interval", r.interval,
			"sweep_interval", r.sweepInterval)
	}
}
