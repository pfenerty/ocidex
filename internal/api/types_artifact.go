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
