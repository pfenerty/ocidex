package api

import (
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// ---------------------------------------------------------------------------
// Artifacts — List
// ---------------------------------------------------------------------------

// ListArtifactsInput is the request for GET /api/v1/artifacts.
type ListArtifactsInput struct {
	CursorParams
	Type       string `query:"type" doc:"Filter by artifact type"`
	Name       string `query:"name" doc:"Filter by artifact name"`
	Sufficient string `query:"sufficient" doc:"Filter to artifacts with sufficiently enriched SBOMs; pass 'false' to include all (default: true)"`
	// Sorting by severity changes what the opaque cursor carries — the counts
	// are a rollup that gets rewritten under a reader, so the page is an
	// offset rather than a keyset position (ADR-043 rule 1). A cursor issued
	// under one sort is rejected under the other, since its arity differs.
	Sort string `query:"sort" enum:"severity" doc:"Column to sort by. Empty orders by name. Changing it invalidates any cursor already held."`
	Dir  string `query:"dir"  enum:"asc,desc"  doc:"Sort direction; defaults to desc (worst first) when sort is set."`
}

// ListMyArtifactsInput is the request for GET /api/v1/users/me/artifacts. It
// embeds ListArtifactsInput so the two stay filter-for-filter identical.
type ListMyArtifactsInput struct {
	ListArtifactsInput
}

// ListArtifactsOutput is the response for GET /api/v1/artifacts.
type ListArtifactsOutput struct {
	Body struct {
		Data       []service.ArtifactSummary `json:"data"`
		Pagination CursorMeta                `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// Artifacts — Get
// ---------------------------------------------------------------------------

// GetArtifactInput is the request for GET /api/v1/artifacts/{id}.
type GetArtifactInput struct {
	ID string `path:"id" doc:"Artifact UUID" format:"uuid"`
}

// GetArtifactOutput is the response for GET /api/v1/artifacts/{id}.
type GetArtifactOutput struct {
	Body service.ArtifactDetail
}

// ---------------------------------------------------------------------------
// Artifacts — Lookup (ADR-042)
// ---------------------------------------------------------------------------

// LookupArtifactInput is the request for GET /api/v1/artifacts/lookup.
//
// The key travels in the query string, not a path segment, because container
// artifact names are full repository paths containing slashes (ADR-042 R1).
type LookupArtifactInput struct {
	Name  string `query:"name" required:"true" doc:"Exact artifact name, e.g. ghcr.io/pfenerty/ocidex"`
	Type  string `query:"type" doc:"Optional artifact type qualifier; omit or leave empty to match any type"`
	Group string `query:"group" doc:"Optional artifact group qualifier; omit or leave empty to match any group"`
}

// ---------------------------------------------------------------------------
// Artifacts — Delete
// ---------------------------------------------------------------------------

// DeleteArtifactInput is the request for DELETE /api/v1/artifacts/{id}.
type DeleteArtifactInput struct {
	ID string `path:"id" doc:"Artifact UUID" format:"uuid"`
}

// ---------------------------------------------------------------------------
// Artifacts — SBOMs
// ---------------------------------------------------------------------------

// ListArtifactSBOMsInput is the request for GET /api/v1/artifacts/{id}/sboms.
type ListArtifactSBOMsInput struct {
	CursorParams
	ID             string `path:"id" doc:"Artifact UUID" format:"uuid"`
	SubjectVersion string `query:"subject_version" doc:"Filter by subject version"`
	ImageVersion   string `query:"image_version"   doc:"Filter by image version"`
}

// ListArtifactSBOMsOutput is the response for GET /api/v1/artifacts/{id}/sboms.
type ListArtifactSBOMsOutput struct {
	Body struct {
		Data       []service.SBOMSummary `json:"data"`
		Pagination CursorMeta            `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// Artifacts — Versions
// ---------------------------------------------------------------------------

// ListArtifactVersionsInput is the request for GET /api/v1/artifacts/{id}/versions.
type ListArtifactVersionsInput struct {
	PaginationParams
	ID   string `path:"id" doc:"Artifact UUID" format:"uuid"`
	Mode string `query:"mode" enum:"semver,all" doc:"Sort/filter mode: 'semver' (semver versions, semver order), 'all' (every version, build-time order). Empty auto-selects semver when available."`
	// Sort is a column ordering layered on top of Mode, not a third mode: Mode
	// also decides which versions appear at all, so sorting must not touch it.
	Sort string `query:"sort" enum:"severity" doc:"Column to sort by, applied on top of mode. Empty keeps the mode's own ordering."`
	Dir  string `query:"dir"  enum:"asc,desc"  doc:"Sort direction; defaults to desc (worst first) when sort is set."`
}

// ArtifactVersionSummary is a single version row returned by the versions endpoint.
type ArtifactVersionSummary struct {
	VersionKey    string     `json:"versionKey"`
	SbomID        string     `json:"sbomId"`
	SBOMCount     int64      `json:"sbomCount" doc:"Total number of SBOMs ingested for this version"`
	Architectures []string   `json:"architectures"`
	ImageVersion  *string    `json:"imageVersion,omitempty"`
	Revision      *string    `json:"revision,omitempty"`
	SourceURL     *string    `json:"sourceUrl,omitempty"`
	BuildDate     *time.Time `json:"buildDate,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	Sufficient    bool       `json:"sufficient"`
	SigningStatus string     `json:"signingStatus" enum:"unsigned,signed,verified,verification_failed,artifact_missing" doc:"Signing status derived from provenance enrichment"`
	// Omitted rather than zeroed when nothing is known, so a client cannot read
	// "never scanned" as "clean" (ADR-044).
	Vulns *service.VulnSummary `json:"vulns,omitempty" doc:"Severity counts for this version's newest SBOM. Absent means no findings are recorded, which may mean it was never scanned — do not render it as zero."`
}

// ListArtifactVersionsOutput is the response for GET /api/v1/artifacts/{id}/versions.
type ListArtifactVersionsOutput struct {
	Body struct {
		Data         []ArtifactVersionSummary `json:"data"`
		Pagination   PaginationMeta           `json:"pagination"`
		HasSemver    bool                     `json:"hasSemver" doc:"Whether the artifact has any semver-parseable version"`
		ResolvedMode string                   `json:"resolvedMode" enum:"semver,all" doc:"Concrete sort mode applied after auto-resolution"`
	}
}

// ---------------------------------------------------------------------------
// Artifacts — Changelog
// ---------------------------------------------------------------------------

// GetArtifactChangelogInput is the request for GET /api/v1/artifacts/{id}/changelog.
type GetArtifactChangelogInput struct {
	ID             string `path:"id"               doc:"Artifact UUID"    format:"uuid"`
	SubjectVersion string `query:"subject_version" doc:"Filter by subject version"`
	Arch           string `query:"arch"            doc:"Architecture to show timeline for (e.g. amd64)"`
	Flavor         string `query:"flavor"          doc:"Flavor to show timeline for (e.g. standard, fips)"`
	Mode           string `query:"mode" enum:"semver,all" doc:"Sort/filter mode: 'semver' (semver versions, semver order), 'all' (every version, build-time order). Empty auto-selects semver when available."`
	// The maximum is 100 rather than PaginationParams' 200: each entry carries
	// a full component diff, so a page is far heavier here than a row is
	// elsewhere.
	Limit  int32 `query:"limit"  default:"20" minimum:"1" maximum:"100" doc:"Maximum number of changelog entries per page"`
	Offset int32 `query:"offset" default:"0"  minimum:"0"                doc:"Number of entries to skip, counting from the newest"`
}

// GetArtifactChangelogOutput is the response for GET /api/v1/artifacts/{id}/changelog.
type GetArtifactChangelogOutput struct {
	Body service.Changelog
}

// ---------------------------------------------------------------------------
// Artifacts — License Summary
// ---------------------------------------------------------------------------

// GetArtifactLicenseSummaryInput is the request for GET /api/v1/artifacts/{id}/license-summary.
type GetArtifactLicenseSummaryInput struct {
	ID string `path:"id" doc:"Artifact UUID" format:"uuid"`
}

// GetArtifactLicenseSummaryOutput is the response for GET /api/v1/artifacts/{id}/license-summary.
type GetArtifactLicenseSummaryOutput struct {
	Body struct {
		Licenses []service.LicenseCount `json:"licenses"`
	}
}

// GetArtifactVulnSummaryInput is the request for GET /api/v1/artifacts/{id}/vuln-summary.
type GetArtifactVulnSummaryInput struct {
	ID string `path:"id" doc:"Artifact UUID" format:"uuid"`
}

// GetArtifactVulnSummaryOutput is the response for GET /api/v1/artifacts/{id}/vuln-summary.
type GetArtifactVulnSummaryOutput struct {
	Body struct {
		Summary *service.VulnSummary `json:"summary"`
	}
}

// GetArtifactUsagesInput is the request for GET /api/v1/artifacts/{id}/usages.
type GetArtifactUsagesInput struct {
	ID string `path:"id" doc:"Artifact UUID" format:"uuid"`
}

// GetArtifactUsagesOutput is the response for GET /api/v1/artifacts/{id}/usages.
type GetArtifactUsagesOutput struct {
	Body struct {
		Usages []service.ArtifactRelation `json:"usages"`
	}
}

// GetArtifactContainsInput is the request for GET /api/v1/artifacts/{id}/contains.
type GetArtifactContainsInput struct {
	ID string `path:"id" doc:"Artifact UUID" format:"uuid"`
}

// GetArtifactContainsOutput is the response for GET /api/v1/artifacts/{id}/contains.
type GetArtifactContainsOutput struct {
	Body struct {
		Contains []service.ArtifactRelation `json:"contains"`
	}
}

// ListArtifactVulnsInput is the request for GET /api/v1/artifacts/{id}/vulns.
//
// Offset pagination for the same reason as ListSBOMVulnsInput: numbered pages
// (ADR-043 rule 3) over computed aggregates with no immutable cursor tuple.
type ListArtifactVulnsInput struct {
	ID       string `path:"id" doc:"Artifact UUID" format:"uuid"`
	Severity string `query:"severity" enum:"CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN" doc:"Filter by severity"`
	// Vuln closes the reverse trail: /vulnerabilities/{id} links here for one
	// advisory rather than dropping the reader into an unfiltered list.
	Vuln string `query:"vuln" doc:"Filter to a single advisory, by canonical id or native OSV id"`
	Sort string `query:"sort" enum:"severity,cvss_score,affected_package_count,affected_version_count,canonical_id" doc:"Column to sort by. Unset means worst first: severity, then CVSS."`
	Dir  string `query:"dir" enum:"asc,desc" doc:"Sort direction (default asc). Applies to sort only — with sort unset the worst-first default ordering ignores it."`
	// VersionScope bounds the versions scanned, newest version first. The list
	// is computed over the newest SBOM of each version in scope, so its cost
	// scales with this rather than with the artifact's whole history.
	VersionScope int32 `query:"versionScope" default:"20" minimum:"1" maximum:"200" doc:"How many of the artifact's most recent versions to scan"`
	PaginationParams
}

// ListArtifactVulnsOutput is the response for GET /api/v1/artifacts/{id}/vulns.
//
// VersionScope and TotalVersions are on the body rather than left implicit
// because the list is a truncation of the artifact's history: without them a
// reader cannot tell "clean" from "clean in the versions we looked at".
type ListArtifactVulnsOutput struct {
	Body struct {
		Data       []service.ArtifactVulnEntry `json:"data"`
		Pagination PaginationMeta              `json:"pagination"`
		// VersionScope is how many versions were scanned, newest first.
		VersionScope int32 `json:"versionScope"`
		// TotalVersions is how many versions the artifact has in all.
		TotalVersions int64 `json:"totalVersions"`
	}
}
