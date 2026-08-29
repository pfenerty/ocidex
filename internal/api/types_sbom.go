package api

import "github.com/pfenerty/ocidex/internal/service"

// ---------------------------------------------------------------------------
// SBOM — Ingest
// ---------------------------------------------------------------------------

// IngestSBOMInput is the request for POST /api/v1/sbom.
type IngestSBOMInput struct {
	RawBody      []byte
	Source       string `query:"source"       doc:"Ingest channel this SBOM arrived through, as a source UUID or <namespace>/<name>. Required — the source's namespace owns the SBOM."`
	Version      string `query:"version"      doc:"Image version/tag (overrides BOM-extracted value for subject_version and imageVersion)"`
	Architecture string `query:"architecture" doc:"Image architecture (e.g. amd64, arm64)"`
	BuildDate    string `query:"build_date"   doc:"Image build date (RFC3339 or date string)"`

	// Caller-declared subject identity (ADR-040). A `syft dir:` BOM describes
	// the directory it walked, so a non-container uploader has to say what the
	// SBOM is about; each field overrides its BOM-extracted counterpart.
	SubjectType  string `query:"subject_type"  doc:"CycloneDX component type of the subject (e.g. application, library, file)"`
	SubjectName  string `query:"subject_name"  doc:"Subject name (e.g. ocidex)"`
	SubjectGroup string `query:"subject_group" doc:"Subject group/namespace (e.g. github.com/pfenerty)"`
	SubjectPurl  string `query:"subject_purl"  doc:"Subject package URL (e.g. pkg:golang/github.com/pfenerty/ocidex@v1.2.3)"`
	Digest       string `query:"digest"        doc:"sha256 of the artifact file itself, not of this SBOM document. Required for a non-container subject."`
}

// IngestSBOMOutput is the response for POST /api/v1/sbom.
type IngestSBOMOutput struct {
	Body struct {
		ID             string `json:"id" doc:"UUID of the created SBOM"`
		Status         string `json:"status" example:"accepted" doc:"Ingestion status"`
		SpecVersion    string `json:"specVersion" doc:"CycloneDX spec version"`
		SerialNumber   string `json:"serialNumber,omitempty" doc:"SBOM serial number"`
		ComponentCount int    `json:"componentCount" doc:"Number of components in the SBOM"`
	}
}

// ---------------------------------------------------------------------------
// SBOM — List
// ---------------------------------------------------------------------------

// ListSBOMsInput is the request for GET /api/v1/sbom.
type ListSBOMsInput struct {
	CursorParams
	SerialNumber string `query:"serial_number" doc:"Filter by serial number"`
	Digest       string `query:"digest" doc:"Filter by image digest"`
}

// ListSBOMsOutput is the response for GET /api/v1/sbom.
type ListSBOMsOutput struct {
	Body struct {
		Data       []service.SBOMSummary `json:"data"`
		Pagination CursorMeta            `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// SBOM — Get
// ---------------------------------------------------------------------------

// GetSBOMInput is the request for GET /api/v1/sbom/{id}.
type GetSBOMInput struct {
	ID      string `path:"id" doc:"SBOM UUID" format:"uuid"`
	Include string `query:"include" doc:"Set to 'raw' to include the raw BOM JSON"`
}

// GetSBOMOutput is the response for GET /api/v1/sbom/{id}.
type GetSBOMOutput struct {
	Body service.SBOMDetail
}

// ---------------------------------------------------------------------------
// SBOM — Lookup (ADR-042)
// ---------------------------------------------------------------------------

// LookupSBOMInput is the request for GET /api/v1/sboms/lookup. It accepts two
// mutually sufficient forms: the qualifier ladder (artifact + version, then
// arch, then flavor) or Digest on its own.
type LookupSBOMInput struct {
	Artifact string `query:"artifact" doc:"Exact artifact name, e.g. ghcr.io/pfenerty/ocidex; required unless digest is given"`
	Version  string `query:"version" doc:"Artifact version, e.g. 1.2.3; required unless digest is given"`
	Arch     string `query:"arch" doc:"Optional architecture qualifier; omit or leave empty to match any architecture"`
	Flavor   string `query:"flavor" doc:"Optional image flavor qualifier (ADR-020); omit or leave empty to match any flavor"`
	Digest   string `query:"digest" doc:"SBOM digest. Unique by construction, so this form never returns 409; supply it instead of artifact and version"`
	Include  string `query:"include" doc:"Set to 'raw' to include the raw BOM JSON"`
}

// ---------------------------------------------------------------------------
// SBOM — Dependencies
// ---------------------------------------------------------------------------

// GetSBOMDependenciesInput is the request for GET /api/v1/sbom/{id}/dependencies.
type GetSBOMDependenciesInput struct {
	ID string `path:"id" doc:"SBOM UUID" format:"uuid"`
}

// GetSBOMDependenciesOutput is the response for GET /api/v1/sbom/{id}/dependencies.
type GetSBOMDependenciesOutput struct {
	Body service.DependencyGraph
}

// ---------------------------------------------------------------------------
// SBOM — Components
// ---------------------------------------------------------------------------

// ListSBOMComponentsInput is the request for GET /api/v1/sbom/{id}/components.
type ListSBOMComponentsInput struct {
	CursorParams
	ID string `path:"id" doc:"SBOM UUID" format:"uuid"`
	// Sorting by severity changes what the opaque cursor carries — the counts
	// come from package_vulnerability, which the feed rewrites under a reader,
	// so the page is an offset rather than a keyset position (ADR-043 rule 1).
	// A cursor issued under one sort is rejected under the other: its arity
	// differs, so it fails to decode rather than silently skipping rows.
	Sort string `query:"sort" enum:"severity" doc:"Column to sort by. Empty orders by name. Changing it invalidates any cursor already held."`
	Dir  string `query:"dir"  enum:"asc,desc"  doc:"Sort direction; defaults to desc (worst first) when sort is set."`
}

// ListSBOMComponentsOutput is the response for GET /api/v1/sbom/{id}/components.
type ListSBOMComponentsOutput struct {
	Body struct {
		Components []service.ComponentSummary `json:"components"`
		Pagination CursorMeta                 `json:"pagination"`
	}
}

// ListSBOMVulnsInput is the request for GET /api/v1/sboms/{id}/vulns.
//
// Offset pagination, not a keyset cursor: the tab renders numbered pages, which
// is ADR-043 rule 3. The sort keys are computed aggregates over an alias group,
// so there is no stable immutable tuple to key a cursor on either.
type ListSBOMVulnsInput struct {
	ID       string `path:"id" doc:"SBOM UUID" format:"uuid"`
	Severity string `query:"severity" enum:"CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN" doc:"Filter by severity"`
	Sort     string `query:"sort" enum:"severity,cvss_score,affected_package_count,canonical_id" doc:"Column to sort by. Unset means worst first: severity, then CVSS."`
	Dir      string `query:"dir" enum:"asc,desc" doc:"Sort direction (default asc). Applies to sort only — with sort unset the worst-first default ordering ignores it."`
	PaginationParams
}

// ListSBOMVulnsOutput is the response for GET /api/v1/sboms/{id}/vulns.
type ListSBOMVulnsOutput struct {
	Body struct {
		Data       []service.SBOMVulnEntry `json:"data"`
		Pagination PaginationMeta          `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// SBOM — Delete
// ---------------------------------------------------------------------------

// DeleteSBOMInput is the request for DELETE /api/v1/sbom/{id}.
type DeleteSBOMInput struct {
	ID string `path:"id" doc:"SBOM UUID" format:"uuid"`
}

// ---------------------------------------------------------------------------
// SBOM — Drift history
// ---------------------------------------------------------------------------

// ListSBOMDriftHistoryInput is the request for GET /api/v1/sboms/{id}/drift.
type ListSBOMDriftHistoryInput struct {
	CursorParams
	ID string `path:"id" doc:"SBOM UUID" format:"uuid"`
}

// ListSBOMDriftHistoryOutput is the response for GET /api/v1/sboms/{id}/drift.
type ListSBOMDriftHistoryOutput struct {
	Body struct {
		Data       []service.ProvenanceDriftSummary `json:"data"`
		Pagination CursorMeta                       `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

// DiffSBOMsInput is the request for GET /api/v1/sboms/diff.
type DiffSBOMsInput struct {
	From string `query:"from" required:"true" doc:"UUID of the source SBOM" format:"uuid"`
	To   string `query:"to" required:"true" doc:"UUID of the target SBOM" format:"uuid"`
}

// DiffSBOMsOutput is the response for GET /api/v1/sboms/diff.
type DiffSBOMsOutput struct {
	Body service.ChangelogEntry
}

// DiffTreeInput is the request for GET /api/v1/sboms/diff-tree.
type DiffTreeInput struct {
	From string `query:"from" required:"true" doc:"UUID of the source SBOM" format:"uuid"`
	To   string `query:"to" required:"true" doc:"UUID of the target SBOM" format:"uuid"`
}

// DiffTreeOutput is the response for GET /api/v1/sboms/diff-tree.
type DiffTreeOutput struct {
	Body service.DiffTree
}
