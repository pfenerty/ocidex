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
		TopArtifacts       []service.DiscoverArtifact `json:"top_artifacts" doc:"Artifacts ranked by how widely they are used, how many versions are tracked, and how recently they were seen"`
		RecentArtifacts    []service.DiscoverRecent   `json:"recent_artifacts" doc:"Most recently updated public artifacts, one row per artifact"`
		TopVulnerabilities []service.DiscoverVuln     `json:"top_vulnerabilities" doc:"Vulnerabilities ranked by how many public artifacts they affect"`
		LicenseSpread      []service.DiscoverLicense  `json:"license_spread" doc:"License distribution across public content, by distinct package identity"`
		GeneratedAt        string                     `json:"generated_at,omitempty" doc:"When this snapshot was computed; absent while warming"`
		Warming            bool                       `json:"warming" doc:"No snapshot is available yet, so every section is empty because nothing is known — not because the catalog is empty; render a loading state and retry"`
	}
}
