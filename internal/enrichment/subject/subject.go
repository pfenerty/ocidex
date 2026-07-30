// Package subject defines the identity type enrichers use to locate the
// artifact being enriched. It exists as a leaf package so enricher
// subpackages (e.g. internal/enrichment/provenance) can depend on it without
// importing the root internal/enrichment package, which would create an
// import cycle for enrichers whose subpackage the root package also needs to
// import (e.g. for drift detection).
package subject

import "github.com/jackc/pgx/v5/pgtype"

// Ref identifies what to enrich. It carries the SBOM identity and the
// artifact metadata needed by enrichers.
type Ref struct {
	SBOMId         pgtype.UUID
	RegistryID     pgtype.UUID // registry this SBOM was ingested under; scopes per-registry trust config
	ArtifactType   string
	ArtifactName   string
	Digest         string
	IndexDigest    string // multi-arch index this child came from; provenance lives here, not on the child
	SubjectVersion string // tag hint for parent index lookup
	Architecture   string // caller-supplied at ingest time
	BuildDate      string // caller-supplied at ingest time (RFC3339 or date string)
}
