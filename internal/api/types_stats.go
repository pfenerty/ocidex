package api

import "github.com/pfenerty/ocidex/internal/service"

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
	Q        string `query:"q" maxLength:"128" doc:"Filter by vulnerability id (CVE/GHSA/OSV), substring match against the canonical id and its aliases"`
	Severity string `query:"severity" enum:"CRITICAL,HIGH,MEDIUM,LOW" doc:"Filter by severity"`
	Sort     string `query:"sort" enum:"severity,cvss_score,affected_sbom_count,affected_purl_count,published_at,canonical_id" doc:"Sort field"`
	SortDir  string `query:"sort_dir" enum:"asc,desc" doc:"Sort direction (asc or desc)"`
}

// ListMyVulnerabilitiesInput is the request for GET /api/v1/users/me/vulns. It
// embeds ListTopVulnerabilitiesInput so the two stay filter-for-filter
// identical.
type ListMyVulnerabilitiesInput struct {
	ListTopVulnerabilitiesInput
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
		// NamespaceCount describes the whole affected set, not the page.
		// Pagination.Total counts artifacts, which answers "how much of the
		// catalog" — a different question from "how many teams".
		NamespaceCount int64 `json:"namespaceCount" doc:"Namespaces visible to the caller that hold at least one affected SBOM"`
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
