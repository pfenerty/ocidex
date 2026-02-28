// Package enrichment defines the enrichment pipeline for post-ingestion data enrichment.
// Each enricher implements the Enricher interface and is registered with a Dispatcher
// that runs background workers to process enrichment requests asynchronously.
package enrichment

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pfenerty/ocidex/internal/repository"
)

// SubjectRef identifies what to enrich. It carries the SBOM identity
// and the artifact metadata needed by enrichers.
type SubjectRef struct {
	SBOMId         pgtype.UUID
	ArtifactType   string
	ArtifactName   string
	Digest         string
	SubjectVersion string // tag hint for parent index lookup
}

// Enricher is implemented by each enrichment source (OCI metadata, vuln scan, etc.).
type Enricher interface {
	// Name returns a unique identifier for this enricher (e.g., "oci-metadata").
	Name() string

	// CanEnrich reports whether this enricher applies to the given subject.
	CanEnrich(ref SubjectRef) bool

	// Enrich performs the enrichment and returns the result as JSON bytes.
	// The context carries the cancellation signal.
	Enrich(ctx context.Context, ref SubjectRef) ([]byte, error)
}

// Store persists enrichment results. Implemented by the repository layer.
type Store interface {
	UpsertEnrichment(ctx context.Context, arg repository.UpsertEnrichmentParams) error
	UpdateSBOMSubjectVersion(ctx context.Context, arg repository.UpdateSBOMSubjectVersionParams) error
}
