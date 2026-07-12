package enrichmentworker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/repository"
)

// enrichmentGetter is the narrow read seam needed to check whether a
// dependent's prerequisites have succeeded.
type enrichmentGetter interface {
	GetEnrichment(ctx context.Context, arg repository.GetEnrichmentParams) (repository.Enrichment, error)
}

// enqueuer is the narrow write seam needed to enqueue a dependent job.
type enqueuer interface {
	Enqueue(ctx context.Context, sbomID pgtype.UUID, architecture, buildDate, enricherName string) error
}

// hintPublisher is the narrow seam over jetstream.JetStream needed to publish
// the completion-driven ".enrich.hint" doorbell.
type hintPublisher interface {
	PublishMsgAsync(msg *nats.Msg, opts ...jetstream.PublishOpt) (jetstream.PubAckFuture, error)
}

// enqueueDependents enqueues every enricher that declares completedEnricher as
// a prerequisite, provided all of that dependent's prerequisites have reached
// status=success. It reuses the existing enrichment_jobs outbox (Enqueue is
// idempotent per sbom+enricher) and the ".enrich.hint" NATS doorbell — no new
// tables or subjects. Best-effort: enqueue/publish failures are logged and
// skipped rather than propagated, matching submitter.go's fire-and-forget hint.
func enqueueDependents(
	ctx context.Context,
	store enrichmentGetter,
	jobSvc enqueuer,
	js hintPublisher,
	streamName string,
	sbomID pgtype.UUID,
	architecture, buildDate, completedEnricher string,
	logger *slog.Logger,
) {
	for _, dep := range enrichment.Dependents(completedEnricher) {
		ready := true
		for _, prereq := range enrichment.Prerequisites(dep) {
			row, err := store.GetEnrichment(ctx, repository.GetEnrichmentParams{SbomID: sbomID, EnricherName: prereq})
			if err != nil || row.Status != "success" {
				ready = false
				break
			}
		}
		if !ready {
			continue
		}

		if err := jobSvc.Enqueue(ctx, sbomID, architecture, buildDate, dep); err != nil {
			logger.Error("enrichment-worker: dependent enqueue failed",
				"sbom_id", uuidToHex(sbomID), "enricher", dep, "err", err,
			)
			continue
		}
		publishHint(js, streamName, sbomID, logger)
	}
}

func publishHint(js hintPublisher, streamName string, sbomID pgtype.UUID, logger *slog.Logger) {
	jobID := uuidToHex(sbomID)
	hint, err := json.Marshal(struct {
		ID string `json:"id"`
	}{ID: jobID})
	if err != nil {
		return
	}

	msg := nats.NewMsg(streamName + ".enrich.hint")
	msg.Data = hint
	if _, err := js.PublishMsgAsync(msg); err != nil {
		logger.Warn("enrichment-worker: dependent hint publish failed; poll loop will pick up",
			"sbom_id", jobID, "err", err,
		)
	}
}

func uuidToHex(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
