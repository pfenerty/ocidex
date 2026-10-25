package api

import "github.com/pfenerty/ocidex/internal/service"

// ---------------------------------------------------------------------------
// Stats — Dashboard Summary
// ---------------------------------------------------------------------------

// DashboardStatsOutput is the response for GET /api/v1/stats/summary.
type DashboardStatsOutput struct {
	Body struct {
		ArtifactCount         int64                    `json:"artifactCount"`
		SBOMCount             int64                    `json:"sbomCount"`
		PackageCount          int64                    `json:"packageCount"`
		VersionCount          int64                    `json:"versionCount"`
		LicenseCount          int64                    `json:"licenseCount"`
		ArtifactTypes         []ArtifactTypeCountEntry `json:"artifactTypes"`
		LicenseCategories     []CategoryCountEntry     `json:"licenseCategories"`
		IngestionTimeline     []DailyCountEntry        `json:"ingestionTimeline"`
		PackageGrowthTimeline []DailyCountEntry        `json:"packageGrowthTimeline"`
		VersionGrowthTimeline []DailyCountEntry        `json:"versionGrowthTimeline"`
		TopPackages           []PackageSummaryEntry    `json:"topPackages"`
		VulnCount             int64                    `json:"vulnCount"`
		VulnSeverity          VulnSeverityEntry        `json:"vulnSeverity"`
		Warming               bool                     `json:"warming" doc:"No snapshot is available yet and every count is a zero placeholder; render a loading state and retry"`
	}
}

// ArtifactTypeCountEntry is the number of tracked artifacts of one CycloneDX type.
type ArtifactTypeCountEntry struct {
	Type          string `json:"type"`
	ArtifactCount int64  `json:"artifactCount"`
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
	Sort     string `query:"sort" enum:"severity,cvssScore,affectedSbomCount,affectedPurlCount,publishedAt,canonicalId" doc:"Sort field"`
	SortDir  string `query:"sortDir" enum:"asc,desc" doc:"Sort direction (asc or desc)"`
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
	ComponentCount int64  `json:"componentCount"`
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
	VersionCount int64   `json:"versionCount"`
	SbomCount    int64   `json:"sbomCount"`
}
