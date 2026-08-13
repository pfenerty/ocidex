package api

import (
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

// PaginationParams is embedded in input structs for paginated endpoints.
type PaginationParams struct {
	Limit  int32 `query:"limit" default:"20" minimum:"1" maximum:"200" doc:"Maximum number of results per page"`
	Offset int32 `query:"offset" default:"0" minimum:"0" doc:"Number of results to skip"`
}

// PaginationMeta contains pagination metadata in response bodies.
type PaginationMeta struct {
	Total  int64 `json:"total" doc:"Total number of matching results"`
	Limit  int32 `json:"limit" doc:"The limit that was applied"`
	Offset int32 `json:"offset" doc:"The offset that was applied"`
}

// CursorParams is embedded in input structs for keyset-paginated endpoints.
// Keyset paging replaces OFFSET (which scans-and-discards on deep pages) and
// drops the per-page COUNT(*) total; the client pages forward with an opaque
// cursor and stops when hasMore is false.
type CursorParams struct {
	Limit  int32  `query:"limit" default:"20" minimum:"1" maximum:"200" doc:"Maximum number of results per page"`
	Cursor string `query:"cursor" doc:"Opaque cursor from a previous response's nextCursor; omit for the first page"`
}

// CursorMeta contains keyset-pagination metadata in response bodies.
type CursorMeta struct {
	Limit      int32   `json:"limit" doc:"The limit that was applied"`
	HasMore    bool    `json:"hasMore" doc:"Whether more results exist after this page"`
	NextCursor *string `json:"nextCursor,omitempty" doc:"Opaque cursor to fetch the next page; null when hasMore is false"`
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

// HealthCheckOutput is the response for GET /health.
type HealthCheckOutput struct {
	Body struct {
		Status string `json:"status" example:"ok" doc:"Health status"`
	}
}

// ReadinessCheckOutput is the response for GET /ready.
type ReadinessCheckOutput struct {
	Body struct {
		Status string `json:"status" example:"ready" doc:"Readiness status"`
		Reason string `json:"reason,omitempty" doc:"Reason for unavailability"`
	}
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

// VersionOutput is the response for GET /api/v1/.
type VersionOutput struct {
	Body struct {
		Version string `json:"version" example:"v1" doc:"API version"`
	}
}

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
}

// ListSBOMComponentsOutput is the response for GET /api/v1/sbom/{id}/components.
type ListSBOMComponentsOutput struct {
	Body struct {
		Components []service.ComponentSummary `json:"components"`
		Pagination CursorMeta                 `json:"pagination"`
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
	PaginationParams
	ID string `path:"id" doc:"SBOM UUID" format:"uuid"`
}

// ListSBOMDriftHistoryOutput is the response for GET /api/v1/sboms/{id}/drift.
type ListSBOMDriftHistoryOutput struct {
	Body struct {
		Data       []service.ProvenanceDriftSummary `json:"data"`
		Pagination PaginationMeta                   `json:"pagination"`
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

// ---------------------------------------------------------------------------
// Components — Search
// ---------------------------------------------------------------------------

// SearchComponentsInput is the request for GET /api/v1/components.
type SearchComponentsInput struct {
	PaginationParams
	Name    string `query:"name" doc:"Component name to search for; required unless purl is given"`
	Purl    string `query:"purl" doc:"Exact package URL, e.g. pkg:npm/lodash@4.17.21; the cross-SBOM key for a component (ADR-042 R6)"`
	Group   string `query:"group" doc:"Filter by component group"`
	Version string `query:"version" doc:"Filter by component version"`
}

// SearchComponentsOutput is the response for GET /api/v1/components.
type SearchComponentsOutput struct {
	Body struct {
		Data       []service.ComponentSummary `json:"data"`
		Pagination PaginationMeta             `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// Components — Distinct
// ---------------------------------------------------------------------------

// SearchDistinctComponentsInput is the request for GET /api/v1/components/distinct.
type SearchDistinctComponentsInput struct {
	PaginationParams
	Name     string `query:"name" doc:"Filter by component name"`
	Group    string `query:"group" doc:"Filter by component group"`
	Type     string `query:"type" doc:"Filter by component type"`
	PurlType string `query:"purl_type" doc:"Filter by purl type"`
	Sort     string `query:"sort" doc:"Sort field"`
	SortDir  string `query:"sort_dir" doc:"Sort direction (asc or desc)"`
}

// SearchDistinctComponentsOutput is the response for GET /api/v1/components/distinct.
type SearchDistinctComponentsOutput struct {
	Body struct {
		Data       []service.DistinctComponentSummary `json:"data"`
		Pagination PaginationMeta                     `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// Components — PURL Types
// ---------------------------------------------------------------------------

// ListComponentPurlTypesOutput is the response for GET /api/v1/components/purl-types.
type ListComponentPurlTypesOutput struct {
	Body struct {
		Types []string `json:"types"`
	}
}

// ---------------------------------------------------------------------------
// Components — Versions
// ---------------------------------------------------------------------------

// GetComponentVersionsInput is the request for GET /api/v1/components/versions.
type GetComponentVersionsInput struct {
	Name    string `query:"name" required:"true" doc:"Component name"`
	Group   string `query:"group" doc:"Filter by component group"`
	Version string `query:"version" doc:"Filter by component version"`
	Type    string `query:"type" doc:"Filter by component type"`
}

// GetComponentVersionsOutput is the response for GET /api/v1/components/versions.
type GetComponentVersionsOutput struct {
	Body struct {
		Versions []service.ComponentVersionEntry `json:"versions"`
	}
}

// ---------------------------------------------------------------------------
// Components — Get
// ---------------------------------------------------------------------------

// GetComponentInput is the request for GET /api/v1/components/{id}.
type GetComponentInput struct {
	ID string `path:"id" doc:"Component UUID" format:"uuid"`
}

// GetComponentOutput is the response for GET /api/v1/components/{id}.
type GetComponentOutput struct {
	Body service.ComponentDetail
}

// GetComponentVulnsInput is the request for GET /api/v1/components/{id}/vulns.
type GetComponentVulnsInput struct {
	ID string `path:"id" doc:"Component UUID" format:"uuid"`
}

// GetComponentVulnsOutput is the response for GET /api/v1/components/{id}/vulns.
type GetComponentVulnsOutput struct {
	Body struct {
		Data []service.ComponentVulnEntry `json:"data"`
	}
}

// ---------------------------------------------------------------------------
// Licenses — List
// ---------------------------------------------------------------------------

// ListLicensesInput is the request for GET /api/v1/licenses.
type ListLicensesInput struct {
	PaginationParams
	SpdxID   string `query:"spdx_id" doc:"Filter by SPDX identifier"`
	Name     string `query:"name" doc:"Filter by license name"`
	Category string `query:"category" doc:"Filter by license category"`
}

// ListLicensesOutput is the response for GET /api/v1/licenses.
type ListLicensesOutput struct {
	Body struct {
		Data       []service.LicenseCount `json:"data"`
		Pagination PaginationMeta         `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// Licenses — Components by License
// ---------------------------------------------------------------------------

// ListComponentsByLicenseInput is the request for GET /api/v1/licenses/{id}/components.
type ListComponentsByLicenseInput struct {
	PaginationParams
	ID string `path:"id" doc:"License UUID" format:"uuid"`
}

// ListComponentsByLicenseOutput is the response for GET /api/v1/licenses/{id}/components.
type ListComponentsByLicenseOutput struct {
	Body struct {
		Data       []service.ComponentSummary `json:"data"`
		Pagination PaginationMeta             `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// Licenses — Lookup (ADR-042)
// ---------------------------------------------------------------------------

// LookupLicenseInput is the request for GET /api/v1/licenses/lookup.
type LookupLicenseInput struct {
	SpdxID string `query:"spdxId" required:"true" doc:"SPDX license identifier, e.g. Apache-2.0"`
}

// LookupLicenseOutput is the response for GET /api/v1/licenses/lookup.
type LookupLicenseOutput struct {
	Body service.LicenseCount
}

// ---------------------------------------------------------------------------
// Artifacts — List
// ---------------------------------------------------------------------------

// ListArtifactsInput is the request for GET /api/v1/artifacts.
type ListArtifactsInput struct {
	CursorParams
	Type       string `query:"type" doc:"Filter by artifact type"`
	Name       string `query:"name" doc:"Filter by artifact name"`
	Sufficient string `query:"sufficient" doc:"Filter to artifacts with sufficiently enriched SBOMs; pass 'false' to include all (default: true)"`
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

// ---------------------------------------------------------------------------
// Stats — Dashboard Summary
// ---------------------------------------------------------------------------

// DashboardStatsOutput is the response for GET /api/v1/stats/summary.
type DashboardStatsOutput struct {
	Body struct {
		ArtifactCount         int64                    `json:"artifact_count"`
		SBOMCount             int64                    `json:"sbom_count"`
		PackageCount          int64                    `json:"package_count"`
		VersionCount          int64                    `json:"version_count"`
		LicenseCount          int64                    `json:"license_count"`
		ArtifactTypes         []ArtifactTypeCountEntry `json:"artifact_types"`
		LicenseCategories     []CategoryCountEntry     `json:"license_categories"`
		IngestionTimeline     []DailyCountEntry        `json:"ingestion_timeline"`
		PackageGrowthTimeline []DailyCountEntry        `json:"package_growth_timeline"`
		VersionGrowthTimeline []DailyCountEntry        `json:"version_growth_timeline"`
		TopPackages           []PackageSummaryEntry    `json:"top_packages"`
		VulnCount             int64                    `json:"vuln_count"`
		VulnSeverity          VulnSeverityEntry        `json:"vuln_severity"`
		Warming               bool                     `json:"warming" doc:"No snapshot is available yet and every count is a zero placeholder; render a loading state and retry"`
	}
}

// ArtifactTypeCountEntry is the number of tracked artifacts of one CycloneDX type.
type ArtifactTypeCountEntry struct {
	Type          string `json:"type"`
	ArtifactCount int64  `json:"artifact_count"`
}

// VulnSeverityEntry is a per-severity count of distinct tracked vulnerabilities.
type VulnSeverityEntry struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Unknown  int64 `json:"unknown"`
}

// ListTopVulnerabilitiesInput is the request for GET /api/v1/vulns.
type ListTopVulnerabilitiesInput struct {
	PaginationParams
	Severity string `query:"severity" enum:"CRITICAL,HIGH,MEDIUM,LOW" doc:"Filter by severity"`
	Sort     string `query:"sort" enum:"severity,cvss_score,affected_sbom_count,affected_purl_count,published_at,canonical_id" doc:"Sort field"`
	SortDir  string `query:"sort_dir" enum:"asc,desc" doc:"Sort direction (asc or desc)"`
}

// ListTopVulnerabilitiesOutput is the response for GET /api/v1/vulns.
type ListTopVulnerabilitiesOutput struct {
	Body struct {
		Data       []service.TopVulnEntry `json:"data"`
		Pagination PaginationMeta         `json:"pagination"`
	}
}

// GetVulnerabilityInput is the request for GET /api/v1/vulns/{id}.
type GetVulnerabilityInput struct {
	ID string `path:"id" doc:"Vulnerability ID (CVE or GHSA ID)"`
	PaginationParams
}

// GetVulnerabilityOutput is the response for GET /api/v1/vulns/{id}.
type GetVulnerabilityOutput struct {
	Body struct {
		Vulnerability        service.VulnDetail          `json:"vulnerability"`
		AffectedComponents   []service.AffectedComponent `json:"affectedComponents"`
		ComponentsPagination PaginationMeta              `json:"componentsPagination"`
		AffectedArtifacts    []service.AffectedArtifact  `json:"affectedArtifacts"`
		Pagination           PaginationMeta              `json:"pagination"`
	}
}

// CategoryCountEntry is a license compliance category with component count.
type CategoryCountEntry struct {
	Category       string `json:"category"`
	ComponentCount int64  `json:"component_count"`
}

// DailyCountEntry is a date + SBOM ingestion count.
type DailyCountEntry struct {
	Day   string `json:"day"`
	Count int64  `json:"count"`
}

// PackageSummaryEntry is a distinct package with version and SBOM counts.
type PackageSummaryEntry struct {
	Name         string  `json:"name"`
	Group        *string `json:"group,omitempty"`
	Type         string  `json:"type"`
	VersionCount int64   `json:"version_count"`
	SbomCount    int64   `json:"sbom_count"`
}

// ---------------------------------------------------------------------------
// Auth — Me
// ---------------------------------------------------------------------------

// MeOutput is the response for GET /api/v1/users/me.
type MeOutput struct {
	Body struct {
		ID             string `json:"id" doc:"User UUID"`
		GitHubUsername string `json:"github_username" doc:"GitHub login"`
		Role           string `json:"role" doc:"User role: admin, member, or viewer"`
	}
}

// ---------------------------------------------------------------------------
// Auth — API Keys
// ---------------------------------------------------------------------------

// CreateAPIKeyInput is the request for POST /api/v1/auth/keys.
type CreateAPIKeyInput struct {
	Body struct {
		Name  string `json:"name" minLength:"1" maxLength:"100" doc:"Human-readable label for this key"`
		Scope string `json:"scope,omitempty" enum:"read,read-write" default:"read-write" doc:"Key scope: read (GET only) or read-write (full access)"`
	}
}

// CreateAPIKeyOutput is the response for POST /api/v1/auth/keys.
type CreateAPIKeyOutput struct {
	Body struct {
		Key string `json:"key" doc:"Full API key — shown once, store securely"`
	}
}

// KeyMetaResponse is the display-safe API key representation.
type KeyMetaResponse struct {
	ID         string     `json:"id" doc:"Key UUID"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix" doc:"First 8 characters of the key"`
	Scope      string     `json:"scope" enum:"read,read-write" doc:"Key scope"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// ListAPIKeysOutput is the response for GET /api/v1/auth/keys.
type ListAPIKeysOutput struct {
	Body struct {
		Keys []KeyMetaResponse `json:"keys"`
	}
}

// DeleteAPIKeyInput is the request for DELETE /api/v1/auth/keys/{id}.
type DeleteAPIKeyInput struct {
	ID string `path:"id" doc:"Key UUID" format:"uuid"`
}

// ---------------------------------------------------------------------------
// Auth — Users (admin)
// ---------------------------------------------------------------------------

// UserResponse is the public representation of a user.
type UserResponse struct {
	ID             string `json:"id"`
	GitHubUsername string `json:"github_username"`
	Role           string `json:"role"`
}

// ListUsersOutput is the response for GET /api/v1/users.
type ListUsersOutput struct {
	Body struct {
		Users []UserResponse `json:"users"`
	}
}

// UpdateUserRoleInput is the request for PATCH /api/v1/users/{id}/role.
type UpdateUserRoleInput struct {
	ID   string `path:"id" doc:"User UUID" format:"uuid"`
	Body struct {
		Role string `json:"role" enum:"admin,member,viewer" doc:"New role"`
	}
}

// UpdateUserRoleOutput is the response for PATCH /api/v1/users/{id}/role.
type UpdateUserRoleOutput struct {
	Body UserResponse
}

// ---------------------------------------------------------------------------
// Admin — System Status
// ---------------------------------------------------------------------------

// SystemStatusOutput is the response for GET /api/v1/admin/status.
type SystemStatusOutput struct {
	Body struct {
		Enrichment EnrichmentStatus `json:"enrichment"`
		Scanner    ScannerStatus    `json:"scanner"`
		NATS       NATSStatus       `json:"nats"`
		ScanJobs   ScanJobsStatus   `json:"scan_jobs"`
		DB         DBStatus         `json:"db"`
	}
}

// EnrichmentStatus describes the enrichment pipeline configuration.
type EnrichmentStatus struct {
	Enabled   bool `json:"enabled"`
	Workers   int  `json:"workers"`
	QueueSize int  `json:"queue_size"`
}

// ScannerStatus describes the scanner configuration.
type ScannerStatus struct {
	Enabled       bool `json:"enabled"`
	PollerEnabled bool `json:"poller_enabled"`
}

// NATSStatus describes the NATS JetStream configuration.
type NATSStatus struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

// ScanJobsStatus summarizes scan pipeline job counts.
type ScanJobsStatus struct {
	Queued       int64 `json:"queued"`
	Running      int64 `json:"running"`
	Succeeded24h int64 `json:"succeeded_24h"`
	Failed24h    int64 `json:"failed_24h"`
}

// DBStatus reports database connectivity and latency.
type DBStatus struct {
	OK        bool  `json:"ok"`
	LatencyMs int64 `json:"latency_ms"`
}

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

// RegistryResponse is the public representation of a configured OCI registry.
type RegistryResponse struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Type                string   `json:"type"`
	URL                 string   `json:"url"`
	Insecure            bool     `json:"insecure"`
	HasSecret           bool     `json:"has_secret"`
	HasAuth             bool     `json:"has_auth"`
	Enabled             bool     `json:"enabled"`
	WebhookURL          string   `json:"webhook_url"`
	Repositories        []string `json:"repositories" doc:"Explicit repositories to walk; overrides catalog discovery when non-empty"`
	RepositoryPatterns  []string `json:"repository_patterns" doc:"Glob patterns for repositories to ingest; empty = all"`
	TagPatterns         []string `json:"tag_patterns" doc:"Glob patterns or 'semver' for tags to ingest; empty = all"`
	ScanMode            string   `json:"scan_mode"`
	PollIntervalMinutes int      `json:"poll_interval_minutes"`
	LastPolledAt        *string  `json:"last_polled_at,omitempty"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
	Visibility          string   `json:"visibility" doc:"Registry visibility: public or private"`
	OwnerID             *string  `json:"owner_id,omitempty" doc:"UUID of the registry owner"`
	OwnerUsername       *string  `json:"owner_username,omitempty" doc:"GitHub username of the registry owner"`
	IncludeUntagged     bool     `json:"include_untagged" doc:"Scan untagged manifests via registry-specific APIs (supported: zot, harbor, ghcr)"`
	VerificationMode    string   `json:"verification_mode" enum:"none,public_key,keyless" doc:"Signature verification mode"`
	TrustPublicKey      *string  `json:"trust_public_key,omitempty" doc:"PEM-encoded EC public key for public_key verification mode"`
	TrustIdentity       *string  `json:"trust_identity,omitempty" doc:"Regex matched against the Fulcio certificate SAN; required for keyless verification mode"`
	TrustIssuer         *string  `json:"trust_issuer,omitempty" doc:"Expected OIDC issuer URL; required for keyless verification mode"`
	ManagedBy           *string  `json:"managed_by,omitempty" doc:"External system that owns this registry's configuration (e.g. kubernetes); absent when managed through this API"`
	ManagedRef          *string  `json:"managed_ref,omitempty" doc:"Identifier within the managing system, e.g. '<namespace>/<name>' of the OCIRegistry resource"`
}

// ListRegistriesInput is the request for GET /api/v1/registries.
type ListRegistriesInput struct {
	PaginationParams
}

// ListRegistriesOutput is the response for GET /api/v1/registries.
type ListRegistriesOutput struct {
	Body struct {
		Data       []RegistryResponse `json:"data"`
		Pagination PaginationMeta     `json:"pagination"`
	}
}

// GetRegistryInput is the request for GET /api/v1/registries/{id}.
type GetRegistryInput struct {
	ID string `path:"id" doc:"Registry UUID" format:"uuid"`
}

// GetRegistryOutput is the response for GET /api/v1/registries/{id}.
type GetRegistryOutput struct {
	Body RegistryResponse
}

// GetRegistryByNameInput is the request for GET /api/v1/registries/by-name/{name}.
type GetRegistryByNameInput struct {
	Name string `path:"name" doc:"Registry name"`
}

// GetRegistryByNameOutput is the response for GET /api/v1/registries/by-name/{name}.
type GetRegistryByNameOutput struct {
	Body RegistryResponse
}

// CreateRegistryInput is the request for POST /api/v1/registries.
type CreateRegistryInput struct {
	Body struct {
		Name                string   `json:"name" minLength:"1" maxLength:"100" doc:"Human-readable registry name"`
		Namespace           string   `json:"namespace,omitempty" maxLength:"100" doc:"Namespace to create the registry in, created on first use; omit to give the registry a namespace of its own named after it"`
		Type                string   `json:"type" enum:"zot,harbor,docker,generic,ghcr" doc:"Registry type"`
		URL                 string   `json:"url" minLength:"1" doc:"Registry address (e.g. zot:5000)"`
		Insecure            bool     `json:"insecure" doc:"Allow HTTP (non-TLS) connections"`
		WebhookSecret       *string  `json:"webhook_secret,omitempty" doc:"Bearer token required on incoming webhooks; omit to disable auth"`
		AuthUsername        *string  `json:"auth_username,omitempty" doc:"Username for registry authentication; omit for anonymous access"`
		AuthToken           *string  `json:"auth_token,omitempty" doc:"Token or PAT for registry authentication; omit for anonymous access"`
		Repositories        []string `json:"repositories,omitempty" doc:"Explicit repositories to walk; bypasses /v2/_catalog discovery when non-empty"`
		RepositoryPatterns  []string `json:"repository_patterns,omitempty" doc:"Glob patterns for repositories to ingest; empty = all"`
		TagPatterns         []string `json:"tag_patterns,omitempty" doc:"Glob patterns or 'semver' for tags to ingest; empty = all"`
		ScanMode            string   `json:"scan_mode,omitempty" enum:"webhook,poll,both" doc:"Scanning mode"`
		PollIntervalMinutes int      `json:"poll_interval_minutes,omitempty" minimum:"1" doc:"Minutes between polls"`
		Visibility          string   `json:"visibility,omitempty" enum:"public,private" default:"public" doc:"Registry visibility"`
		IncludeUntagged     bool     `json:"include_untagged,omitempty" doc:"Scan untagged manifests via registry-specific APIs (supported: zot, harbor, ghcr)"`
		VerificationMode    string   `json:"verification_mode,omitempty" enum:"none,public_key,keyless" doc:"Signature verification mode; defaults to none"`
		TrustPublicKey      *string  `json:"trust_public_key,omitempty" doc:"PEM-encoded EC public key; required when verification_mode is public_key"`
		TrustIdentity       *string  `json:"trust_identity,omitempty" doc:"Regex matched against the Fulcio certificate SAN; required when verification_mode is keyless"`
		TrustIssuer         *string  `json:"trust_issuer,omitempty" doc:"Expected OIDC issuer URL; required when verification_mode is keyless"`
		ManagedBy           *string  `json:"managed_by,omitempty" doc:"External system that owns this registry's configuration (e.g. kubernetes); set by that system's controller, not by hand"`
		ManagedRef          *string  `json:"managed_ref,omitempty" doc:"Identifier within the managing system, e.g. '<namespace>/<name>' of the OCIRegistry resource"`
	}
}

// CreateRegistryResponseBody extends RegistryResponse with the generated webhook secret,
// which is returned once on creation and never again.
type CreateRegistryResponseBody struct {
	RegistryResponse
	WebhookSecret string `json:"webhook_secret,omitempty" doc:"Generated webhook secret — shown once only. Store it securely; it cannot be retrieved again."`
}

// CreateRegistryOutput is the response for POST /api/v1/registries.
type CreateRegistryOutput struct {
	Body CreateRegistryResponseBody
}

// RegenerateWebhookSecretInput is the request for POST /api/v1/registries/{id}/webhook-secret.
type RegenerateWebhookSecretInput struct {
	ID string `path:"id" doc:"Registry UUID" format:"uuid"`
}

// RegenerateWebhookSecretOutput is the response for POST /api/v1/registries/{id}/webhook-secret.
type RegenerateWebhookSecretOutput struct {
	Body struct {
		WebhookSecret string `json:"webhook_secret" doc:"New webhook secret — shown once only. The previous secret is immediately invalidated."`
	}
}

// UpdateRegistryInput is the request for PATCH /api/v1/registries/{id}.
type UpdateRegistryInput struct {
	ID   string `path:"id" doc:"Registry UUID" format:"uuid"`
	Body struct {
		Name                string   `json:"name" minLength:"1" maxLength:"100"`
		Type                string   `json:"type" enum:"zot,harbor,docker,generic,ghcr"`
		URL                 string   `json:"url" minLength:"1"`
		Insecure            bool     `json:"insecure"`
		AuthUsername        *string  `json:"auth_username,omitempty"`
		AuthToken           *string  `json:"auth_token,omitempty"`
		Enabled             bool     `json:"enabled"`
		Repositories        []string `json:"repositories,omitempty"`
		RepositoryPatterns  []string `json:"repository_patterns,omitempty"`
		TagPatterns         []string `json:"tag_patterns,omitempty"`
		ScanMode            string   `json:"scan_mode,omitempty" enum:"webhook,poll,both" doc:"Scanning mode"`
		PollIntervalMinutes int      `json:"poll_interval_minutes,omitempty" minimum:"1" doc:"Minutes between polls"`
		Visibility          string   `json:"visibility,omitempty" enum:"public,private" doc:"Registry visibility"`
		IncludeUntagged     bool     `json:"include_untagged,omitempty" doc:"Scan untagged manifests via registry-specific APIs (supported: zot, harbor, ghcr)"`
		VerificationMode    string   `json:"verification_mode,omitempty" enum:"none,public_key,keyless" doc:"Signature verification mode; defaults to none"`
		TrustPublicKey      *string  `json:"trust_public_key,omitempty" doc:"PEM-encoded EC public key; required when verification_mode is public_key"`
		TrustIdentity       *string  `json:"trust_identity,omitempty" doc:"Regex matched against the Fulcio certificate SAN; required when verification_mode is keyless"`
		TrustIssuer         *string  `json:"trust_issuer,omitempty" doc:"Expected OIDC issuer URL; required when verification_mode is keyless"`
		ManagedBy           *string  `json:"managed_by,omitempty" doc:"External system that owns this registry's configuration; omit to leave the existing marker untouched"`
		ManagedRef          *string  `json:"managed_ref,omitempty" doc:"Identifier within the managing system; omit to leave the existing value untouched"`
	}
}

// ScanRegistryInput is the request for POST /api/v1/registries/{id}/scan.
type ScanRegistryInput struct {
	ID    string `path:"id" doc:"Registry UUID" format:"uuid"`
	Force bool   `query:"force" doc:"Re-scan every image, including digests already ingested. Default false: already-scanned digests are skipped."`
}

// ScanRegistryOutput is the response for POST /api/v1/registries/{id}/scan.
type ScanRegistryOutput struct {
	Body struct {
		Message string `json:"message" doc:"Confirmation that ad-hoc scan has been initiated"`
	}
}

// UpdateRegistryOutput is the response for PUT /api/v1/registries/{id}.
type UpdateRegistryOutput struct {
	Body RegistryResponse
}

// DeleteRegistryInput is the request for DELETE /api/v1/registries/{id}.
type DeleteRegistryInput struct {
	ID string `path:"id" doc:"Registry UUID" format:"uuid"`
}

// TestRegistryConnectionInput is the request for POST /api/v1/registries/test-connection.
type TestRegistryConnectionInput struct {
	Body struct {
		URL          string  `json:"url" minLength:"1" doc:"Registry address (e.g. zot:5000)"`
		Insecure     bool    `json:"insecure" doc:"Use HTTP instead of HTTPS"`
		AuthUsername *string `json:"auth_username,omitempty" doc:"Username for registry authentication"`
		AuthToken    *string `json:"auth_token,omitempty" doc:"Token or PAT for registry authentication"`
	}
}

// TestRegistryConnectionOutput is the response for POST /api/v1/registries/test-connection.
type TestRegistryConnectionOutput struct {
	Body struct {
		Reachable bool   `json:"reachable" doc:"Whether the registry responded"`
		Message   string `json:"message" doc:"Human-readable result (e.g. HTTP 200 or error text)"`
	}
}

// RegistryWebhookInput is the request for POST /api/v1/registries/{id}/webhook.
type RegistryWebhookInput struct {
	ID            string `path:"id" doc:"Registry UUID" format:"uuid"`
	Authorization string `header:"Authorization"`
	Body          struct {
		Name      string `json:"name"`
		Reference string `json:"reference"`
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
		Manifest  string `json:"manifest"`
	}
}

// GetRegistryTrustSummaryOutput is the response for GET /api/v1/registries/trust-summary.
// Admin-only: aggregates across all registries, bypassing per-registry visibility.
type GetRegistryTrustSummaryOutput struct {
	Body struct {
		Data []service.RegistryTrustCount `json:"data"`
	}
}

// ListRecentDriftInput is the request for GET /api/v1/registries/drift-feed.
type ListRecentDriftInput struct {
	PaginationParams
}

// ListRecentDriftOutput is the response for GET /api/v1/registries/drift-feed.
// Admin-only: aggregates across all registries, bypassing per-registry visibility.
type ListRecentDriftOutput struct {
	Body struct {
		Data       []service.RecentDriftEntry `json:"data"`
		Pagination PaginationMeta             `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// Scan Jobs
// ---------------------------------------------------------------------------

// ScanJobResponse is the public representation of a scan pipeline job.
type ScanJobResponse struct {
	ID            string  `json:"id" doc:"Job UUID"`
	RegistryID    *string `json:"registry_id,omitempty" doc:"Source registry UUID"`
	Repository    string  `json:"repository"`
	Digest        string  `json:"digest"`
	Tag           *string `json:"tag,omitempty"`
	State         string  `json:"state" enum:"queued,running,succeeded,failed"`
	Attempts      int32   `json:"attempts"`
	LastError     *string `json:"last_error,omitempty"`
	NATSMsgID     *string `json:"nats_msg_id,omitempty" doc:"NATS deduplication message ID"`
	SbomID        *string `json:"sbom_id,omitempty" doc:"Resulting SBOM UUID on success"`
	CreatedAt     string  `json:"created_at"`
	StartedAt     *string `json:"started_at,omitempty"`
	LastAttemptAt *string `json:"last_attempt_at,omitempty"`
	FinishedAt    *string `json:"finished_at,omitempty"`
	WorkerID      *string `json:"worker_id,omitempty" doc:"Pod hostname that is processing this job"`
}

// ListScanJobsInput is the request for GET /api/v1/jobs.
type ListScanJobsInput struct {
	PaginationParams
	State string `query:"state" enum:"queued,running,succeeded,failed" doc:"Filter by job state"`
}

// ListScanJobsOutput is the response for GET /api/v1/jobs.
type ListScanJobsOutput struct {
	Body struct {
		Data       []ScanJobResponse `json:"data"`
		Pagination PaginationMeta    `json:"pagination"`
	}
}

// GetScanJobInput is the request for GET /api/v1/jobs/{id}.
type GetScanJobInput struct {
	ID string `path:"id" doc:"Job UUID"`
}

// GetScanJobOutput is the response for GET /api/v1/jobs/{id}.
type GetScanJobOutput struct {
	Body ScanJobResponse
}

// RetryScanJobInput is the request for POST /api/v1/admin/jobs/{id}/retry.
type RetryScanJobInput struct {
	ID string `path:"id" doc:"Failed scan job UUID to reset back to 'queued'"`
}

// RetryAllFailedScanJobsOutput is the response for POST /api/v1/admin/jobs/retry-failed.
type RetryAllFailedScanJobsOutput struct {
	Body struct {
		Count int64 `json:"count" doc:"Number of rows transitioned from 'failed' to 'queued'"`
	}
}

// EnrichmentJobResponse is the public representation of an enrichment pipeline job.
type EnrichmentJobResponse struct {
	ID            string  `json:"id" doc:"Job UUID"`
	SbomID        *string `json:"sbom_id,omitempty" doc:"SBOM being enriched"`
	EnricherName  string  `json:"enricher_name" doc:"Which enricher this job runs" enum:"user,oci-metadata,provenance"`
	State         string  `json:"state" enum:"queued,running,succeeded,failed"`
	Attempts      int32   `json:"attempts"`
	LastError     *string `json:"last_error,omitempty"`
	WorkerID      *string `json:"worker_id,omitempty" doc:"Pod hostname that is processing this job"`
	SbomDigest    *string `json:"sbom_digest,omitempty" doc:"Digest of the SBOM's image, for display"`
	ArtifactName  *string `json:"artifact_name,omitempty" doc:"Name of the artifact, for display"`
	CreatedAt     string  `json:"created_at"`
	StartedAt     *string `json:"started_at,omitempty"`
	LastAttemptAt *string `json:"last_attempt_at,omitempty"`
	FinishedAt    *string `json:"finished_at,omitempty"`
}

// ListEnrichmentJobsInput is the request for GET /api/v1/enrichment-jobs.
type ListEnrichmentJobsInput struct {
	PaginationParams
	State        string `query:"state" enum:"queued,running,succeeded,failed" doc:"Filter by job state"`
	EnricherName string `query:"enricher_name" enum:"user,oci-metadata,provenance" doc:"Filter by enricher"`
}

// ListEnrichmentJobsOutput is the response for GET /api/v1/enrichment-jobs.
type ListEnrichmentJobsOutput struct {
	Body struct {
		Data       []EnrichmentJobResponse `json:"data"`
		Pagination PaginationMeta          `json:"pagination"`
	}
}

// EnrichmentJobSummaryRow is one (enricher, state) cell of the health matrix.
type EnrichmentJobSummaryRow struct {
	EnricherName string `json:"enricher_name"`
	State        string `json:"state"`
	Count        int64  `json:"count"`
}

// EnrichmentJobsSummaryOutput is the response for GET /api/v1/enrichment-jobs/summary.
type EnrichmentJobsSummaryOutput struct {
	Body struct {
		Data []EnrichmentJobSummaryRow `json:"data"`
	}
}

// RetryEnrichmentJobInput is the request for POST /api/v1/admin/enrichment-jobs/{id}/retry.
type RetryEnrichmentJobInput struct {
	ID string `path:"id" doc:"Failed enrichment job UUID to reset back to 'queued'"`
}

// RetryAllFailedEnrichmentJobsInput is the request for POST /api/v1/admin/enrichment-jobs/retry-failed.
type RetryAllFailedEnrichmentJobsInput struct {
	EnricherName string `query:"enricher_name" enum:"user,oci-metadata,provenance" doc:"Limit the reset to a single enricher; omit to reset all"`
}

// RetryAllFailedEnrichmentJobsOutput is the response for POST /api/v1/admin/enrichment-jobs/retry-failed.
type RetryAllFailedEnrichmentJobsOutput struct {
	Body struct {
		Count int64 `json:"count" doc:"Number of rows transitioned from 'failed' to 'queued'"`
	}
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

// NamespaceResponse is a namespace as returned by the API. A namespace is the
// authorization anchor (ADR-039): ownership and visibility live here, not on
// the sources or registries beneath it.
type NamespaceResponse struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Visibility    string  `json:"visibility" enum:"public,private" doc:"Namespace visibility: public or private"`
	OwnerID       *string `json:"owner_id,omitempty" doc:"UUID of the namespace owner"`
	OwnerUsername *string `json:"owner_username,omitempty" doc:"GitHub username of the namespace owner"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// ListNamespacesInput is the request for GET /api/v1/namespaces.
type ListNamespacesInput struct{}

// ListNamespacesOutput is the response for GET /api/v1/namespaces.
type ListNamespacesOutput struct {
	Body struct {
		Data []NamespaceResponse `json:"data"`
	}
}

// GetNamespaceInput is the request for GET /api/v1/namespaces/{id}.
type GetNamespaceInput struct {
	ID string `path:"id" doc:"Namespace UUID" format:"uuid"`
}

// GetNamespaceOutput is the response for GET /api/v1/namespaces/{id}.
type GetNamespaceOutput struct {
	Body NamespaceResponse
}

// GetNamespaceByNameInput is the request for GET /api/v1/namespaces/by-name/{name}.
type GetNamespaceByNameInput struct {
	Name string `path:"name" doc:"Namespace name"`
}

// GetNamespaceByNameOutput is the response for GET /api/v1/namespaces/by-name/{name}.
type GetNamespaceByNameOutput struct {
	Body NamespaceResponse
}

// CreateNamespaceInput is the request for POST /api/v1/namespaces.
type CreateNamespaceInput struct {
	Body struct {
		Name       string `json:"name" minLength:"1" maxLength:"100" doc:"Human-readable namespace name"`
		Visibility string `json:"visibility,omitempty" enum:"public,private" doc:"Namespace visibility; defaults to private"`
	}
}

// CreateNamespaceOutput is the response for POST /api/v1/namespaces.
type CreateNamespaceOutput struct {
	Body NamespaceResponse
}

// UpdateNamespaceInput is the request for PATCH /api/v1/namespaces/{id}.
type UpdateNamespaceInput struct {
	ID   string `path:"id" doc:"Namespace UUID" format:"uuid"`
	Body struct {
		Name       string `json:"name,omitempty" maxLength:"100" doc:"New namespace name; omit to keep the current one"`
		Visibility string `json:"visibility,omitempty" enum:"public,private" doc:"New visibility; omit to keep the current one"`
	}
}

// UpdateNamespaceOutput is the response for PATCH /api/v1/namespaces/{id}.
type UpdateNamespaceOutput struct {
	Body NamespaceResponse
}

// DeleteNamespaceInput is the request for DELETE /api/v1/namespaces/{id}.
type DeleteNamespaceInput struct {
	ID string `path:"id" doc:"Namespace UUID" format:"uuid"`
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

// SourceResponse is a source as returned by the API. A source is the ingest
// channel an SBOM arrived through (ADR-039); an 'oci_registry' source has a
// matching registry row carrying its pull config and trust policy.
type SourceResponse struct {
	ID            string `json:"id"`
	NamespaceID   string `json:"namespace_id"`
	NamespaceName string `json:"namespace_name,omitempty" doc:"Owning namespace name; populated on list responses"`
	Kind          string `json:"kind" enum:"oci_registry,upload" doc:"Ingest channel kind"`
	Name          string `json:"name"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// ListSourcesInput is the request for GET /api/v1/sources.
type ListSourcesInput struct {
	NamespaceID string `query:"namespace_id" doc:"Limit to sources in this namespace"`
}

// ListSourcesOutput is the response for GET /api/v1/sources.
type ListSourcesOutput struct {
	Body struct {
		Data []SourceResponse `json:"data"`
	}
}

// GetSourceInput is the request for GET /api/v1/sources/{id}.
type GetSourceInput struct {
	ID string `path:"id" doc:"Source UUID" format:"uuid"`
}

// GetSourceOutput is the response for GET /api/v1/sources/{id}.
type GetSourceOutput struct {
	Body SourceResponse
}

// CreateSourceInput is the request for POST /api/v1/sources. Only upload
// sources are created here; an OCI registry source is created together with
// its registry row via POST /api/v1/registries.
type CreateSourceInput struct {
	Body struct {
		NamespaceID string `json:"namespace_id" format:"uuid" doc:"Owning namespace UUID"`
		Name        string `json:"name" minLength:"1" maxLength:"100" doc:"Source name, unique within the namespace"`
	}
}

// CreateSourceOutput is the response for POST /api/v1/sources.
type CreateSourceOutput struct {
	Body SourceResponse
}

// UpdateSourceInput is the request for PATCH /api/v1/sources/{id}. Kind is
// immutable: changing it would strand or orphan the registry subtype row.
type UpdateSourceInput struct {
	ID   string `path:"id" doc:"Source UUID" format:"uuid"`
	Body struct {
		Name string `json:"name" minLength:"1" maxLength:"100" doc:"New source name"`
	}
}

// UpdateSourceOutput is the response for PATCH /api/v1/sources/{id}.
type UpdateSourceOutput struct {
	Body SourceResponse
}

// DeleteSourceInput is the request for DELETE /api/v1/sources/{id}.
type DeleteSourceInput struct {
	ID string `path:"id" doc:"Source UUID" format:"uuid"`
}
