package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// SearchService defines read-only operations for SBOM search and retrieval.
type SearchService interface {
	GetSBOM(ctx context.Context, id pgtype.UUID, includeRaw bool) (SBOMDetail, error)
	ListSBOMs(ctx context.Context, filter SBOMFilter) (PagedResult[SBOMSummary], error)
	SearchComponents(ctx context.Context, filter ComponentFilter) (PagedResult[ComponentSummary], error)
	SearchDistinctComponents(ctx context.Context, filter ComponentFilter) (PagedResult[DistinctComponentSummary], error)
	GetComponentVersions(ctx context.Context, name, group, version, compType string) ([]ComponentVersionEntry, error)
	GetComponent(ctx context.Context, id pgtype.UUID) (ComponentDetail, error)
	ListLicenses(ctx context.Context, filter LicenseFilter) (PagedResult[LicenseCount], error)
	ListComponentsByLicense(ctx context.Context, licenseID pgtype.UUID, limit, offset int32) (PagedResult[ComponentSummary], error)
	GetArtifact(ctx context.Context, id pgtype.UUID) (ArtifactDetail, error)
	ListArtifacts(ctx context.Context, filter ArtifactFilter) (PagedResult[ArtifactSummary], error)
	ListSBOMsByArtifact(ctx context.Context, artifactID pgtype.UUID, subjectVersion, imageVersion string, limit, offset int32) (PagedResult[SBOMSummary], error)
	GetArtifactChangelog(ctx context.Context, artifactID pgtype.UUID, subjectVersion, arch string) (Changelog, error)
	DiffSBOMs(ctx context.Context, fromID, toID pgtype.UUID) (ChangelogEntry, error)
	ListSBOMsByDigest(ctx context.Context, digest string, limit, offset int32) (PagedResult[SBOMSummary], error)
	GetArtifactLicenseSummary(ctx context.Context, artifactID pgtype.UUID) ([]LicenseCount, error)
	GetSBOMDependencies(ctx context.Context, sbomID pgtype.UUID) (DependencyGraph, error)
	ListSBOMComponents(ctx context.Context, sbomID pgtype.UUID) ([]ComponentSummary, error)
	ListComponentPurlTypes(ctx context.Context) ([]string, error)
	GetDashboardStats(ctx context.Context) (*DashboardStats, error)
}

// DashboardStats holds aggregated metrics for the dashboard.
type DashboardStats struct {
	ArtifactCount         int64
	SBOMCount             int64
	PackageCount          int64
	VersionCount          int64
	LicenseCount          int64
	LicenseCategories     []CategoryCount
	IngestionTimeline     []DailyCount
	PackageGrowthTimeline []DailyCount
	VersionGrowthTimeline []DailyCount
	TopPackages           []PackageSummary
}

// PackageSummary is a distinct package with version and SBOM counts.
type PackageSummary struct {
	Name         string  `json:"name"`
	Group        *string `json:"group,omitempty"`
	Type         string  `json:"type"`
	VersionCount int64   `json:"versionCount"`
	SbomCount    int64   `json:"sbomCount"`
}

// CategoryCount is a license compliance category with component count.
type CategoryCount struct {
	Category       string
	ComponentCount int64
}

// DailyCount is a day + SBOM ingestion count for the timeline chart.
type DailyCount struct {
	Day   string
	Count int64
}

// PagedResult wraps a paginated result set.
type PagedResult[T any] struct {
	Data   []T   `json:"data"`
	Total  int64 `json:"total"`
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

// SBOMFilter holds parameters for listing SBOMs.
type SBOMFilter struct {
	SerialNumber string
	Digest       string
	Limit        int32
	Offset       int32
}

// ComponentFilter holds parameters for searching components.
type ComponentFilter struct {
	Name     string
	Group    string
	Version  string
	Type     string
	PurlType string
	Sort     string
	SortDir  string
	Limit    int32
	Offset   int32
}

// LicenseFilter holds parameters for listing licenses.
type LicenseFilter struct {
	SpdxID   string
	Name     string
	Category string
	Limit    int32
	Offset   int32
}

// ArtifactFilter holds parameters for listing artifacts.
type ArtifactFilter struct {
	Type              string
	Name              string
	RequireSufficient bool
	Limit             int32
	Offset            int32
}

// ArtifactSummary is a lightweight artifact representation for list views.
type ArtifactSummary struct {
	ID                  string  `json:"id"`
	Type                string  `json:"type"`
	Name                string  `json:"name"`
	Group               *string `json:"group,omitempty"`
	SbomCount           int64   `json:"sbomCount"`
	SufficientSbomCount int64   `json:"sufficientSbomCount"`
}

// ArtifactDetail extends ArtifactSummary with full metadata.
type ArtifactDetail struct {
	ArtifactSummary
	Purl      *string   `json:"purl,omitempty"`
	Cpe       *string   `json:"cpe,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// SBOMSummary is a lightweight SBOM representation for list views.
type SBOMSummary struct {
	ID             string     `json:"id"`
	SerialNumber   *string    `json:"serialNumber,omitempty"`
	SpecVersion    string     `json:"specVersion"`
	Version        int32      `json:"version"`
	ArtifactID     *string    `json:"artifactId,omitempty"`
	SubjectVersion *string    `json:"subjectVersion,omitempty"`
	Digest         *string    `json:"digest,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	ComponentCount int64      `json:"componentCount,omitempty"`
	BuildDate      *time.Time `json:"buildDate,omitempty"`
	ImageVersion   *string    `json:"imageVersion,omitempty"`
	Architecture   *string    `json:"architecture,omitempty"`
	Revision       *string    `json:"revision,omitempty"`
	SourceURL      *string    `json:"sourceUrl,omitempty"`
	Sufficient     bool       `json:"sufficient"`
}

// SBOMDetail extends SBOMSummary with optional raw BOM data and enrichments.
type SBOMDetail struct {
	SBOMSummary
	RawBOM      json.RawMessage            `json:"rawBom,omitempty"`
	Enrichments map[string]json.RawMessage `json:"enrichments,omitempty"`
}

// ComponentSummary is a lightweight component representation.
type ComponentSummary struct {
	ID      string  `json:"id"`
	SbomID  string  `json:"sbomId"`
	BomRef  *string `json:"bomRef,omitempty"`
	Type    string  `json:"type"`
	Name    string  `json:"name"`
	Group   *string `json:"group,omitempty"`
	Version *string `json:"version,omitempty"`
	Purl    *string `json:"purl,omitempty"`
}

// ComponentDetail extends ComponentSummary with full metadata.
type ComponentDetail struct {
	ComponentSummary
	BomRef       *string            `json:"bomRef,omitempty"`
	Cpe          *string            `json:"cpe,omitempty"`
	Description  *string            `json:"description,omitempty"`
	Scope        *string            `json:"scope,omitempty"`
	Publisher    *string            `json:"publisher,omitempty"`
	Copyright    *string            `json:"copyright,omitempty"`
	Hashes       []HashEntry        `json:"hashes"`
	Licenses     []LicenseSummary   `json:"licenses"`
	ExternalRefs []ExternalRefEntry `json:"externalReferences"`
}

// HashEntry represents a component hash.
type HashEntry struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// LicenseSummary is a lightweight license representation.
type LicenseSummary struct {
	ID     string  `json:"id"`
	SpdxID *string `json:"spdxId,omitempty"`
	Name   string  `json:"name"`
	URL    *string `json:"url,omitempty"`
}

// ExternalRefEntry represents an external reference.
type ExternalRefEntry struct {
	Type    string  `json:"type"`
	URL     string  `json:"url"`
	Comment *string `json:"comment,omitempty"`
}

// LicenseCount represents a license with its component count and compliance category.
type LicenseCount struct {
	ID             string  `json:"id"`
	SpdxID         *string `json:"spdxId,omitempty"`
	Name           string  `json:"name"`
	URL            *string `json:"url,omitempty"`
	ComponentCount int64   `json:"componentCount"`
	Category       string  `json:"category"`
}

// DistinctComponentSummary represents a unique component (by name+group+type) with counts.
type DistinctComponentSummary struct {
	Name         string   `json:"name"`
	Group        *string  `json:"group,omitempty"`
	Type         string   `json:"type"`
	PurlTypes    []string `json:"purlTypes,omitempty"`
	VersionCount int64    `json:"versionCount"`
	SbomCount    int64    `json:"sbomCount"`
}

// ComponentVersionEntry represents a specific version of a component and the SBOM it came from.
type ComponentVersionEntry struct {
	ID             string  `json:"id"`
	SbomID         string  `json:"sbomId"`
	Type           string  `json:"type"`
	Name           string  `json:"name"`
	Group          *string `json:"group,omitempty"`
	Version        *string `json:"version,omitempty"`
	Purl           *string `json:"purl,omitempty"`
	ArtifactID     *string `json:"artifactId,omitempty"`
	SubjectVersion *string `json:"subjectVersion,omitempty"`
	SbomDigest     *string `json:"sbomDigest,omitempty"`
	ArtifactName   *string `json:"artifactName,omitempty"`
	SbomCreatedAt  string  `json:"sbomCreatedAt"`
	Architecture   *string `json:"architecture,omitempty"`
}

// DependencyGraph represents the dependency structure of an SBOM.
type DependencyGraph struct {
	Nodes []ComponentSummary `json:"nodes"`
	Edges []DependencyEdge   `json:"edges"`
}

// DependencyEdge represents a directed dependency relationship.
type DependencyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type searchService struct {
	pool *pgxpool.Pool
}

// NewSearchService creates a new SearchService.
func NewSearchService(pool *pgxpool.Pool) SearchService {
	return &searchService{pool: pool}
}

// Ensure *Queries satisfies SearchRepository.
var _ repository.SearchRepository = (*repository.Queries)(nil)

// Helper functions for pgtype → Go type conversion.

func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

func textToPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

func uuidToPtr(u pgtype.UUID) *string {
	if !u.Valid {
		return nil
	}
	s := uuidToString(u)
	return &s
}

func toComponentSummary(id, sbomID pgtype.UUID, bomRef pgtype.Text, typ, name string, group, version, purl pgtype.Text) ComponentSummary {
	return ComponentSummary{
		ID:      uuidToString(id),
		SbomID:  uuidToString(sbomID),
		BomRef:  textToPtr(bomRef),
		Type:    typ,
		Name:    name,
		Group:   textToPtr(group),
		Version: textToPtr(version),
		Purl:    textToPtr(purl),
	}
}

func toLicenseSummary(l repository.License) LicenseSummary {
	return LicenseSummary{
		ID:     uuidToString(l.ID),
		SpdxID: textToPtr(l.SpdxID),
		Name:   l.Name,
		URL:    textToPtr(l.Url),
	}
}
