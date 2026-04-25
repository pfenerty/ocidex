// Package user provides the user enricher, which stores caller-supplied
// metadata (architecture, build date, subject version) as an enrichment
// record immediately after SBOM ingestion.
package user

import (
	"context"
	"encoding/json"

	"github.com/pfenerty/ocidex/internal/enrichment"
)

// Enricher persists caller-supplied ingest metadata as a "user" enrichment
// record so it is queryable before the async OCI enricher completes.
type Enricher struct{}

// NewEnricher creates a user Enricher.
func NewEnricher() *Enricher { return &Enricher{} }

// Name returns "user".
func (e *Enricher) Name() string { return "user" }

// CanEnrich returns true when the subject carries any caller-supplied metadata.
func (e *Enricher) CanEnrich(ref enrichment.SubjectRef) bool {
	return ref.Architecture != "" || ref.BuildDate != "" || ref.SubjectVersion != ""
}

// Enrich builds a JSON payload from the caller-supplied fields in ref.
func (e *Enricher) Enrich(_ context.Context, ref enrichment.SubjectRef) ([]byte, error) {
	data := map[string]string{}
	if ref.Architecture != "" {
		data["architecture"] = ref.Architecture
	}
	if ref.BuildDate != "" {
		data["created"] = ref.BuildDate
	}
	if ref.SubjectVersion != "" {
		data["imageVersion"] = ref.SubjectVersion
	}
	return json.Marshal(data)
}
