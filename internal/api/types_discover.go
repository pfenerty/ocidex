package api

import "github.com/pfenerty/ocidex/internal/service"

// ---------------------------------------------------------------------------
// Discovery — public landing page
// ---------------------------------------------------------------------------

// DiscoveryOutput is the response for GET /api/v1/discover.
//
// The body embeds the service DTOs directly rather than re-declaring them, the
// same way ListTopVulnerabilitiesOutput uses service.TopVulnEntry: there is no
// per-caller shaping to do here, so a second mapping layer would only be a place
// for the two shapes to drift apart.
type DiscoveryOutput struct {
	// CacheControl is set per-response, not as a constant header, because the
	// warming payload must never be cached — an edge that stored it would serve
	// an empty landing page for the full TTL after the snapshot was ready.
	CacheControl string `header:"Cache-Control"`

	Body struct {
		FeaturedArtifacts  []service.DiscoverFeatured `json:"featuredArtifacts" doc:"Featured public artifacts (DISCOVER_FEATURED, in order), each summarised from its newest SBOM"`
		TopArtifacts       []service.DiscoverArtifact `json:"topArtifacts" doc:"Artifacts ranked by how widely they are used, how many versions are tracked, and how recently they were seen"`
		RecentArtifacts    []service.DiscoverRecent   `json:"recentArtifacts" doc:"Most recently updated public artifacts, one row per artifact"`
		TopVulnerabilities []service.DiscoverVuln     `json:"topVulnerabilities" doc:"Vulnerabilities ranked by how many public artifacts they affect"`
		LicenseSpread      []service.DiscoverLicense  `json:"licenseSpread" doc:"License distribution across public content, by distinct package identity"`
		TopPackages        []service.DiscoverPackage  `json:"topPackages" doc:"The package in the most public SBOMs per ecosystem, among those with a known critical or high"`
		CriticalCuts       []service.DiscoverCut      `json:"criticalCuts" doc:"Recent public releases that removed the most criticals, one per artifact"`
		GeneratedAt        string                     `json:"generatedAt,omitempty" doc:"When this snapshot was computed; absent while warming"`
		Warming            bool                       `json:"warming" doc:"No snapshot is available yet, so every section is empty because nothing is known — not because the catalog is empty; render a loading state and retry"`
	}
}
