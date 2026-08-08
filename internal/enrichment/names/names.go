// Package names holds the string values written to the enrichments table.
// It is a leaf package so both internal/enrichment (which produces them) and
// internal/service (which reads them) can depend on one definition without
// either importing the other. See ADR-026 and ADR-033.
package names

// Enricher names — the values stored in enrichments.enricher_name.
const (
	OCIMetadata = "oci-metadata"
	User        = "user"
	Provenance  = "provenance"
	Git         = "git"
)

// Status values stored in enrichments.status.
const (
	StatusSuccess = "success"
	StatusError   = "error"
)
