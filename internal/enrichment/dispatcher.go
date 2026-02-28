package enrichment

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Dispatcher receives enrichment requests and fans them out to registered enrichers.
type Dispatcher struct {
	enrichers []Enricher
	store     Store
	queue     chan SubjectRef
	workers   int
	logger    *slog.Logger
}

// Option configures a Dispatcher.
type Option func(*Dispatcher)

// WithWorkers sets the number of concurrent worker goroutines.
func WithWorkers(n int) Option {
	return func(d *Dispatcher) {
		if n > 0 {
			d.workers = n
		}
	}
}

// WithQueueSize sets the capacity of the enrichment request channel.
func WithQueueSize(n int) Option {
	return func(d *Dispatcher) {
		if n > 0 {
			d.queue = make(chan SubjectRef, n)
		}
	}
}

// WithLogger sets the logger for the dispatcher.
func WithLogger(l *slog.Logger) Option {
	return func(d *Dispatcher) {
		d.logger = l
	}
}

// NewDispatcher creates a dispatcher with the given enrichers and store.
func NewDispatcher(store Store, enrichers []Enricher, opts ...Option) *Dispatcher {
	d := &Dispatcher{
		enrichers: enrichers,
		store:     store,
		queue:     make(chan SubjectRef, 100),
		workers:   2,
		logger:    slog.Default(),
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Submit queues a subject for enrichment. Non-blocking; drops if queue is full.
func (d *Dispatcher) Submit(ref SubjectRef) {
	select {
	case d.queue <- ref:
		d.logger.Debug("enrichment queued",
			"sbom_id", ref.SBOMId,
			"artifact_name", ref.ArtifactName,
		)
	default:
		d.logger.Warn("enrichment queue full, dropping request",
			"artifact_name", ref.ArtifactName,
		)
	}
}

// SubmitWithResult queues a subject for enrichment. Returns true if queued, false if the queue is full.
func (d *Dispatcher) SubmitWithResult(ref SubjectRef) bool {
	select {
	case d.queue <- ref:
		d.logger.Debug("enrichment queued", "sbom_id", ref.SBOMId, "artifact_name", ref.ArtifactName)
		return true
	default:
		d.logger.Warn("enrichment queue full", "artifact_name", ref.ArtifactName)
		return false
	}
}

// Run starts the worker goroutines and blocks until the context is cancelled.
// Workers drain the queue before returning.
func (d *Dispatcher) Run(ctx context.Context) {
	d.logger.Info("enrichment dispatcher starting",
		"workers", d.workers,
		"enrichers", len(d.enrichers),
	)

	var wg sync.WaitGroup
	for i := range d.workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			d.worker(ctx, id)
		}(i)
	}

	// Wait for context cancellation, then close queue to signal workers to drain and exit.
	<-ctx.Done()
	close(d.queue)
	wg.Wait()

	d.logger.Info("enrichment dispatcher stopped")
}

func (d *Dispatcher) worker(ctx context.Context, id int) {
	d.logger.Debug("enrichment worker started", "worker_id", id)

	for ref := range d.queue {
		d.processSubject(ctx, ref)
	}
}

func (d *Dispatcher) processSubject(ctx context.Context, ref SubjectRef) {
	for _, e := range d.enrichers {
		if !e.CanEnrich(ref) {
			continue
		}

		d.logger.Info("running enricher",
			"enricher", e.Name(),
			"artifact_name", ref.ArtifactName,
		)

		data, err := e.Enrich(ctx, ref)

		params := repository.UpsertEnrichmentParams{
			SbomID:       ref.SBOMId,
			EnricherName: e.Name(),
		}

		if err != nil {
			d.logger.Error("enrichment failed",
				"enricher", e.Name(),
				"artifact_name", ref.ArtifactName,
				"err", err,
			)
			params.Status = "error"
			params.ErrorMessage = pgtype.Text{String: err.Error(), Valid: true}
		} else {
			params.Status = "success"
			params.Data = data
		}

		if storeErr := d.store.UpsertEnrichment(ctx, params); storeErr != nil {
			d.logger.Error("failed to store enrichment result",
				"enricher", e.Name(),
				"artifact_name", ref.ArtifactName,
				"err", storeErr,
			)
		}

		if err == nil && e.Name() == "oci-metadata" {
			d.applyOCIVersion(ctx, ref.SBOMId, data)
		}
	}
}

// applyOCIVersion reads imageVersion from OCI enrichment JSON and updates
// sbom.subject_version to the authoritative annotation value.
func (d *Dispatcher) applyOCIVersion(ctx context.Context, sbomID pgtype.UUID, data []byte) {
	var meta struct {
		ImageVersion string `json:"imageVersion"`
	}
	if err := json.Unmarshal(data, &meta); err != nil || meta.ImageVersion == "" {
		return
	}
	if err := d.store.UpdateSBOMSubjectVersion(ctx, repository.UpdateSBOMSubjectVersionParams{
		ID:             sbomID,
		SubjectVersion: pgtype.Text{String: meta.ImageVersion, Valid: true},
	}); err != nil {
		d.logger.Error("failed to update subject_version from OCI annotations",
			"sbom_id", sbomID,
			"image_version", meta.ImageVersion,
			"err", err,
		)
	}
}
