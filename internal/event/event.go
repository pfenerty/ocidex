// Package event defines the in-process event bus for OCIDex.
// Services publish typed events after state changes; extensions subscribe
// to react asynchronously (enrichment, audit logging, webhooks, etc.).
package event

import "github.com/jackc/pgx/v5/pgtype"

// Type identifies a category of event.
type Type string

const (
	SBOMIngested    Type = "sbom.ingested"
	SBOMDeleted     Type = "sbom.deleted"
	ArtifactCreated Type = "artifact.created"
	ArtifactDeleted Type = "artifact.deleted"
)

// Event is the envelope passed to handlers.
type Event struct {
	Type Type
	Data any
}

// SBOMIngestedData is published after a new SBOM is successfully committed.
type SBOMIngestedData struct {
	SBOMID         pgtype.UUID
	ArtifactType   string
	ArtifactName   string
	Digest         string
	SubjectVersion string
}

// SBOMDeletedData is published after an SBOM is deleted.
type SBOMDeletedData struct {
	SBOMID pgtype.UUID
}

// ArtifactDeletedData is published after an artifact and its SBOMs are deleted.
type ArtifactDeletedData struct {
	ArtifactID pgtype.UUID
}
