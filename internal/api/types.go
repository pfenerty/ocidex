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
	Limit  int32 `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"Maximum number of results per page"`
	Offset int32 `query:"offset" default:"0" minimum:"0" doc:"Number of results to skip"`
}

// PaginationMeta contains pagination metadata in response bodies.
type PaginationMeta struct {
	Total  int64 `json:"total" doc:"Total number of matching results"`
	Limit  int32 `json:"limit" doc:"The limit that was applied"`
	Offset int32 `json:"offset" doc:"The offset that was applied"`
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
	Version      string `query:"version"      doc:"Image version/tag (overrides BOM-extracted value for subject_version and imageVersion)"`
	Architecture string `query:"architecture" doc:"Image architecture (e.g. amd64, arm64)"`
	BuildDate    string `query:"build_date"   doc:"Image build date (RFC3339 or date string)"`
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
	PaginationParams
	SerialNumber string `query:"serial_number" doc:"Filter by serial number"`
	Digest       string `query:"digest" doc:"Filter by image digest"`
}

// ListSBOMsOutput is the response for GET /api/v1/sbom.
type ListSBOMsOutput struct {
	Body struct {
		Data       []service.SBOMSummary `json:"data"`
		Pagination PaginationMeta        `json:"pagination"`
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
	ID string `path:"id" doc:"SBOM UUID" format:"uuid"`
}

// ListSBOMComponentsOutput is the response for GET /api/v1/sbom/{id}/components.
type ListSBOMComponentsOutput struct {
	Body struct {
		Components []service.ComponentSummary `json:"components"`
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

// ---------------------------------------------------------------------------
// Components — Search
// ---------------------------------------------------------------------------

// SearchComponentsInput is the request for GET /api/v1/components.
type SearchComponentsInput struct {
	PaginationParams
	Name    string `query:"name" required:"true" doc:"Component name to search for"`
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
// Artifacts — List
// ---------------------------------------------------------------------------

// ListArtifactsInput is the request for GET /api/v1/artifacts.
type ListArtifactsInput struct {
	PaginationParams
	Type       string `query:"type" doc:"Filter by artifact type"`
	Name       string `query:"name" doc:"Filter by artifact name"`
	Sufficient string `query:"sufficient" doc:"Filter to artifacts with sufficiently enriched SBOMs; pass 'false' to include all (default: true)"`
}

// ListArtifactsOutput is the response for GET /api/v1/artifacts.
type ListArtifactsOutput struct {
	Body struct {
		Data       []service.ArtifactSummary `json:"data"`
		Pagination PaginationMeta            `json:"pagination"`
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
	PaginationParams
	ID             string `path:"id" doc:"Artifact UUID" format:"uuid"`
	SubjectVersion string `query:"subject_version" doc:"Filter by subject version"`
	ImageVersion   string `query:"image_version"   doc:"Filter by image version"`
}

// ListArtifactSBOMsOutput is the response for GET /api/v1/artifacts/{id}/sboms.
type ListArtifactSBOMsOutput struct {
	Body struct {
		Data       []service.SBOMSummary `json:"data"`
		Pagination PaginationMeta        `json:"pagination"`
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

// ---------------------------------------------------------------------------
// Stats — Dashboard Summary
// ---------------------------------------------------------------------------

// DashboardStatsOutput is the response for GET /api/v1/stats/summary.
type DashboardStatsOutput struct {
	Body struct {
		ArtifactCount         int64                 `json:"artifact_count"`
		SBOMCount             int64                 `json:"sbom_count"`
		PackageCount          int64                 `json:"package_count"`
		VersionCount          int64                 `json:"version_count"`
		LicenseCount          int64                 `json:"license_count"`
		LicenseCategories     []CategoryCountEntry  `json:"license_categories"`
		IngestionTimeline     []DailyCountEntry     `json:"ingestion_timeline"`
		PackageGrowthTimeline []DailyCountEntry     `json:"package_growth_timeline"`
		VersionGrowthTimeline []DailyCountEntry     `json:"version_growth_timeline"`
		TopPackages           []PackageSummaryEntry `json:"top_packages"`
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
		Name string `json:"name" minLength:"1" maxLength:"100" doc:"Human-readable label for this key"`
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
	Enabled bool `json:"enabled"`
}

// NATSStatus describes the NATS JetStream configuration.
type NATSStatus struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
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
}

// ListRegistriesOutput is the response for GET /api/v1/registries.
type ListRegistriesOutput struct {
	Body struct {
		Registries []RegistryResponse `json:"registries"`
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

// CreateRegistryInput is the request for POST /api/v1/registries.
type CreateRegistryInput struct {
	Body struct {
		Name                string   `json:"name" minLength:"1" maxLength:"100" doc:"Human-readable registry name"`
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
	}
}

// CreateRegistryOutput is the response for POST /api/v1/registries.
type CreateRegistryOutput struct {
	Body RegistryResponse
}

// UpdateRegistryInput is the request for PUT /api/v1/registries/{id}.
type UpdateRegistryInput struct {
	ID   string `path:"id" doc:"Registry UUID" format:"uuid"`
	Body struct {
		Name                string   `json:"name" minLength:"1" maxLength:"100"`
		Type                string   `json:"type" enum:"zot,harbor,docker,generic,ghcr"`
		URL                 string   `json:"url" minLength:"1"`
		Insecure            bool     `json:"insecure"`
		WebhookSecret       *string  `json:"webhook_secret,omitempty"`
		AuthUsername        *string  `json:"auth_username,omitempty"`
		AuthToken           *string  `json:"auth_token,omitempty"`
		Enabled             bool     `json:"enabled"`
		Repositories        []string `json:"repositories,omitempty"`
		RepositoryPatterns  []string `json:"repository_patterns,omitempty"`
		TagPatterns         []string `json:"tag_patterns,omitempty"`
		ScanMode            string   `json:"scan_mode,omitempty" enum:"webhook,poll,both" doc:"Scanning mode"`
		PollIntervalMinutes int      `json:"poll_interval_minutes,omitempty" minimum:"1" doc:"Minutes between polls"`
	}
}

// ScanRegistryInput is the request for POST /api/v1/registries/{id}/scan.
type ScanRegistryInput struct {
	ID string `path:"id" doc:"Registry UUID" format:"uuid"`
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
