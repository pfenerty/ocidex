package api

import "github.com/pfenerty/ocidex/internal/service"

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
