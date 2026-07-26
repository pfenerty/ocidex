package enrichment

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// recheckBatchSize caps how many SBOMs are requeued per tick, so a large
// backlog of due recheck candidates can't overwhelm the job queue at once.
const recheckBatchSize = 500

// RecheckStore is the subset of the repository needed to find and requeue
// provenance enrichments due for periodic re-verification.
type RecheckStore interface {
	ListSBOMsDueForProvenanceRecheck(ctx context.Context, arg repository.ListSBOMsDueForProvenanceRecheckParams) ([]pgtype.UUID, error)
	RequeueSucceededEnrichmentJob(ctx context.Context, arg repository.RequeueSucceededEnrichmentJobParams) (int64, error)
}

// Reverifier periodically requeues the provenance enrichment job for SBOMs
// whose last successful check is older than Interval, so drift (a trust
// config change, or a registry deleting the artifact) gets detected even
// though nothing else re-triggers enrichment after initial ingest.
type Reverifier struct {
	store    RecheckStore
	interval time.Duration
	logger   *slog.Logger
}

// NewReverifier constructs a Reverifier. interval is how old a provenance
// enrichment's last check must be before it's requeued.
func NewReverifier(store RecheckStore, interval time.Duration, logger *slog.Logger) *Reverifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reverifier{store: store, interval: interval, logger: logger}
}

// Run ticks every hour and requeues due SBOMs. Blocks until ctx is cancelled.
func (r *Reverifier) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
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
			EnricherName: "provenance",
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
}
