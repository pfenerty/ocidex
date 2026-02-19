package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
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
	ListSBOMsByArtifact(ctx context.Context, artifactID pgtype.UUID, subjectVersion string, limit, offset int32) (PagedResult[SBOMSummary], error)
	GetArtifactChangelog(ctx context.Context, artifactID pgtype.UUID, subjectVersion string) (Changelog, error)
	DiffSBOMs(ctx context.Context, fromID, toID pgtype.UUID) (ChangelogEntry, error)
	ListSBOMsByDigest(ctx context.Context, digest string, limit, offset int32) (PagedResult[SBOMSummary], error)
	GetArtifactLicenseSummary(ctx context.Context, artifactID pgtype.UUID) ([]LicenseCount, error)
	GetSBOMDependencies(ctx context.Context, sbomID pgtype.UUID) (DependencyGraph, error)
	ListSBOMComponents(ctx context.Context, sbomID pgtype.UUID) ([]ComponentSummary, error)
	ListComponentPurlTypes(ctx context.Context) ([]string, error)
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
	Type   string
	Name   string
	Limit  int32
	Offset int32
}

// ArtifactSummary is a lightweight artifact representation for list views.
type ArtifactSummary struct {
	ID        string  `json:"id"`
	Type      string  `json:"type"`
	Name      string  `json:"name"`
	Group     *string `json:"group,omitempty"`
	SbomCount int64   `json:"sbomCount"`
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

func (s *searchService) GetSBOM(ctx context.Context, id pgtype.UUID, includeRaw bool) (SBOMDetail, error) {
	q := repository.New(s.pool)

	row, err := q.GetSBOM(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SBOMDetail{}, ErrNotFound
		}
		return SBOMDetail{}, fmt.Errorf("getting sbom: %w", err)
	}

	count, err := q.CountSBOMComponents(ctx, id)
	if err != nil {
		return SBOMDetail{}, fmt.Errorf("counting components: %w", err)
	}

	detail := SBOMDetail{
		SBOMSummary: SBOMSummary{
			ID:             uuidToString(row.ID),
			SerialNumber:   textToPtr(row.SerialNumber),
			SpecVersion:    row.SpecVersion,
			Version:        row.Version,
			ArtifactID:     uuidToPtr(row.ArtifactID),
			SubjectVersion: textToPtr(row.SubjectVersion),
			Digest:         textToPtr(row.Digest),
			CreatedAt:      row.CreatedAt.Time,
			ComponentCount: count,
		},
	}

	if includeRaw {
		raw, err := q.GetSBOMRaw(ctx, id)
		if err != nil {
			return SBOMDetail{}, fmt.Errorf("getting raw bom: %w", err)
		}
		detail.RawBOM = raw
	}

	// Fetch enrichment data for this SBOM.
	enrichRows, err := q.ListEnrichmentsBySBOM(ctx, id)
	if err != nil {
		return SBOMDetail{}, fmt.Errorf("listing enrichments: %w", err)
	}
	for _, e := range enrichRows {
		if e.Status != "success" || len(e.Data) == 0 {
			continue
		}
		if detail.Enrichments == nil {
			detail.Enrichments = make(map[string]json.RawMessage)
		}
		detail.Enrichments[e.EnricherName] = json.RawMessage(e.Data)
	}

	return detail, nil
}

func (s *searchService) ListSBOMs(ctx context.Context, filter SBOMFilter) (PagedResult[SBOMSummary], error) {
	q := repository.New(s.pool)

	rows, err := q.ListSBOMs(ctx, repository.ListSBOMsParams{
		SerialNumber: textOrNull(filter.SerialNumber),
		Digest:       textOrNull(filter.Digest),
		RowLimit:     filter.Limit,
		RowOffset:    filter.Offset,
	})
	if err != nil {
		return PagedResult[SBOMSummary]{}, fmt.Errorf("listing sboms: %w", err)
	}

	var total int64
	items := make([]SBOMSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		items = append(items, SBOMSummary{
			ID:             uuidToString(row.ID),
			SerialNumber:   textToPtr(row.SerialNumber),
			SpecVersion:    row.SpecVersion,
			Version:        row.Version,
			ArtifactID:     uuidToPtr(row.ArtifactID),
			SubjectVersion: textToPtr(row.SubjectVersion),
			Digest:         textToPtr(row.Digest),
			CreatedAt:      row.CreatedAt.Time,
		})
	}

	return PagedResult[SBOMSummary]{
		Data:   items,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (s *searchService) SearchComponents(ctx context.Context, filter ComponentFilter) (PagedResult[ComponentSummary], error) {
	q := repository.New(s.pool)

	rows, err := q.SearchComponents(ctx, repository.SearchComponentsParams{
		Name:      filter.Name,
		GroupName: textOrNull(filter.Group),
		Version:   textOrNull(filter.Version),
		RowLimit:  filter.Limit,
		RowOffset: filter.Offset,
	})
	if err != nil {
		return PagedResult[ComponentSummary]{}, fmt.Errorf("searching components: %w", err)
	}

	var total int64
	items := make([]ComponentSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		items = append(items, toComponentSummary(row.ID, row.SbomID, pgtype.Text{}, row.Type, row.Name, row.GroupName, row.Version, row.Purl))
	}

	return PagedResult[ComponentSummary]{
		Data:   items,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (s *searchService) SearchDistinctComponents(ctx context.Context, filter ComponentFilter) (PagedResult[DistinctComponentSummary], error) {
	q := repository.New(s.pool)

	var namePat pgtype.Text
	if filter.Name != "" {
		namePat = pgtype.Text{String: "%" + filter.Name + "%", Valid: true}
	}
	sortBy := filter.Sort
	switch sortBy {
	case "name", "version_count", "sbom_count":
	default:
		sortBy = "name"
	}
	sortDir := filter.SortDir
	switch sortDir {
	case "asc", "desc":
	default:
		sortDir = "asc"
	}

	rows, err := q.SearchDistinctComponents(ctx, repository.SearchDistinctComponentsParams{
		Name:      namePat,
		GroupName: textOrNull(filter.Group),
		Type:      textOrNull(filter.Type),
		PurlType:  textOrNull(filter.PurlType),
		SortBy:    sortBy,
		SortDir:   sortDir,
		RowLimit:  filter.Limit,
		RowOffset: filter.Offset,
	})
	if err != nil {
		return PagedResult[DistinctComponentSummary]{}, fmt.Errorf("searching distinct components: %w", err)
	}

	var total int64
	items := make([]DistinctComponentSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		var purlTypes []string
		if s, ok := row.PurlTypes.(string); ok && s != "" {
			purlTypes = strings.Split(s, ",")
		}
		items = append(items, DistinctComponentSummary{
			Name:         row.Name,
			Group:        textToPtr(row.GroupName),
			Type:         row.Type,
			PurlTypes:    purlTypes,
			VersionCount: row.VersionCount,
			SbomCount:    row.SbomCount,
		})
	}

	return PagedResult[DistinctComponentSummary]{
		Data:   items,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (s *searchService) GetComponentVersions(ctx context.Context, name, group, version, compType string) ([]ComponentVersionEntry, error) {
	q := repository.New(s.pool)

	rows, err := q.GetComponentVersions(ctx, repository.GetComponentVersionsParams{
		Name:      name,
		GroupName: textOrNull(group),
		Version:   textOrNull(version),
		Type:      textOrNull(compType),
	})
	if err != nil {
		return nil, fmt.Errorf("getting component versions: %w", err)
	}

	items := make([]ComponentVersionEntry, 0, len(rows))
	for _, row := range rows {
		items = append(items, ComponentVersionEntry{
			ID:             uuidToString(row.ID),
			SbomID:         uuidToString(row.SbomID),
			Type:           row.Type,
			Name:           row.Name,
			Group:          textToPtr(row.GroupName),
			Version:        textToPtr(row.Version),
			Purl:           textToPtr(row.Purl),
			ArtifactID:     uuidToPtr(row.ArtifactID),
			SubjectVersion: textToPtr(row.SubjectVersion),
			SbomDigest:     textToPtr(row.SbomDigest),
			ArtifactName:   textToPtr(row.ArtifactName),
			SbomCreatedAt:  row.SbomCreatedAt.Time.Format(time.RFC3339),
		})
	}

	return items, nil
}

func (s *searchService) GetComponent(ctx context.Context, id pgtype.UUID) (ComponentDetail, error) {
	q := repository.New(s.pool)

	row, err := q.GetComponent(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ComponentDetail{}, ErrNotFound
		}
		return ComponentDetail{}, fmt.Errorf("getting component: %w", err)
	}

	hashes, err := q.ListComponentHashes(ctx, id)
	if err != nil {
		return ComponentDetail{}, fmt.Errorf("listing hashes: %w", err)
	}

	licenses, err := q.ListComponentLicenses(ctx, id)
	if err != nil {
		return ComponentDetail{}, fmt.Errorf("listing licenses: %w", err)
	}

	extRefs, err := q.ListComponentExtRefs(ctx, id)
	if err != nil {
		return ComponentDetail{}, fmt.Errorf("listing ext refs: %w", err)
	}

	hashEntries := make([]HashEntry, 0, len(hashes))
	for _, h := range hashes {
		hashEntries = append(hashEntries, HashEntry{Algorithm: h.Algorithm, Value: h.Value})
	}

	licEntries := make([]LicenseSummary, 0, len(licenses))
	for _, l := range licenses {
		licEntries = append(licEntries, toLicenseSummary(l))
	}

	refEntries := make([]ExternalRefEntry, 0, len(extRefs))
	for _, r := range extRefs {
		refEntries = append(refEntries, ExternalRefEntry{
			Type:    r.Type,
			URL:     r.Url,
			Comment: textToPtr(r.Comment),
		})
	}

	return ComponentDetail{
		ComponentSummary: toComponentSummary(row.ID, row.SbomID, row.BomRef, row.Type, row.Name, row.GroupName, row.Version, row.Purl),
		BomRef:           textToPtr(row.BomRef),
		Cpe:              textToPtr(row.Cpe),
		Description:      textToPtr(row.Description),
		Scope:            textToPtr(row.Scope),
		Publisher:        textToPtr(row.Publisher),
		Copyright:        textToPtr(row.Copyright),
		Hashes:           hashEntries,
		Licenses:         licEntries,
		ExternalRefs:     refEntries,
	}, nil
}

func (s *searchService) ListLicenses(ctx context.Context, filter LicenseFilter) (PagedResult[LicenseCount], error) {
	q := repository.New(s.pool)

	rows, err := q.ListLicenses(ctx, repository.ListLicensesParams{
		SpdxID:    textOrNull(filter.SpdxID),
		Name:      textOrNull(filter.Name),
		Category:  textOrNull(filter.Category),
		RowLimit:  filter.Limit,
		RowOffset: filter.Offset,
	})
	if err != nil {
		return PagedResult[LicenseCount]{}, fmt.Errorf("listing licenses: %w", err)
	}

	var total int64
	items := make([]LicenseCount, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		spdx := textToPtr(row.SpdxID)
		items = append(items, LicenseCount{
			ID:             uuidToString(row.ID),
			SpdxID:         spdx,
			Name:           row.Name,
			URL:            textToPtr(row.Url),
			ComponentCount: row.ComponentCount,
			Category:       classifyLicense(spdx),
		})
	}

	return PagedResult[LicenseCount]{
		Data:   items,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (s *searchService) ListComponentsByLicense(ctx context.Context, licenseID pgtype.UUID, limit, offset int32) (PagedResult[ComponentSummary], error) {
	q := repository.New(s.pool)

	rows, err := q.ListComponentsByLicense(ctx, repository.ListComponentsByLicenseParams{
		LicenseID: licenseID,
		RowLimit:  limit,
		RowOffset: offset,
	})
	if err != nil {
		return PagedResult[ComponentSummary]{}, fmt.Errorf("listing components by license: %w", err)
	}

	var total int64
	items := make([]ComponentSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		items = append(items, toComponentSummary(row.ID, row.SbomID, pgtype.Text{}, row.Type, row.Name, row.GroupName, row.Version, row.Purl))
	}

	return PagedResult[ComponentSummary]{
		Data:   items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

func (s *searchService) GetArtifact(ctx context.Context, id pgtype.UUID) (ArtifactDetail, error) {
	q := repository.New(s.pool)

	row, err := q.GetArtifact(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ArtifactDetail{}, ErrNotFound
		}
		return ArtifactDetail{}, fmt.Errorf("getting artifact: %w", err)
	}

	// Get SBOM count via ListArtifacts with a filter matching this artifact.
	// More efficient: just count directly.
	sbomRows, err := q.ListSBOMsByArtifact(ctx, repository.ListSBOMsByArtifactParams{
		ArtifactID:     id,
		SubjectVersion: pgtype.Text{}, // no filter — count all SBOMs
		RowLimit:       1,
		RowOffset:      0,
	})
	if err != nil {
		return ArtifactDetail{}, fmt.Errorf("counting sboms: %w", err)
	}

	var sbomCount int64
	if len(sbomRows) > 0 {
		sbomCount = sbomRows[0].TotalCount
	}

	return ArtifactDetail{
		ArtifactSummary: ArtifactSummary{
			ID:        uuidToString(row.ID),
			Type:      row.Type,
			Name:      row.Name,
			Group:     textToPtr(row.GroupName),
			SbomCount: sbomCount,
		},
		Purl:      textToPtr(row.Purl),
		Cpe:       textToPtr(row.Cpe),
		CreatedAt: row.CreatedAt.Time,
	}, nil
}

func (s *searchService) ListArtifacts(ctx context.Context, filter ArtifactFilter) (PagedResult[ArtifactSummary], error) {
	q := repository.New(s.pool)

	rows, err := q.ListArtifacts(ctx, repository.ListArtifactsParams{
		Type:      textOrNull(filter.Type),
		Name:      textOrNull(filter.Name),
		RowLimit:  filter.Limit,
		RowOffset: filter.Offset,
	})
	if err != nil {
		return PagedResult[ArtifactSummary]{}, fmt.Errorf("listing artifacts: %w", err)
	}

	var total int64
	items := make([]ArtifactSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		items = append(items, ArtifactSummary{
			ID:        uuidToString(row.ID),
			Type:      row.Type,
			Name:      row.Name,
			Group:     textToPtr(row.GroupName),
			SbomCount: row.SbomCount,
		})
	}

	return PagedResult[ArtifactSummary]{
		Data:   items,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (s *searchService) ListSBOMsByArtifact(ctx context.Context, artifactID pgtype.UUID, subjectVersion string, limit, offset int32) (PagedResult[SBOMSummary], error) {
	q := repository.New(s.pool)

	rows, err := q.ListSBOMsByArtifact(ctx, repository.ListSBOMsByArtifactParams{
		ArtifactID:     artifactID,
		SubjectVersion: textOrNull(subjectVersion),
		RowLimit:       limit,
		RowOffset:      offset,
	})
	if err != nil {
		return PagedResult[SBOMSummary]{}, fmt.Errorf("listing sboms by artifact: %w", err)
	}

	artifactIDStr := uuidToString(artifactID)
	var total int64
	items := make([]SBOMSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		summary := SBOMSummary{
			ID:             uuidToString(row.ID),
			SerialNumber:   textToPtr(row.SerialNumber),
			SpecVersion:    row.SpecVersion,
			Version:        row.Version,
			ArtifactID:     &artifactIDStr,
			SubjectVersion: textToPtr(row.SubjectVersion),
			Digest:         textToPtr(row.Digest),
			CreatedAt:      row.CreatedAt.Time,
			ComponentCount: row.ComponentCount,
		}
		if row.BuildDate.Valid {
			t := row.BuildDate.Time
			summary.BuildDate = &t
		}
		items = append(items, summary)
	}

	return PagedResult[SBOMSummary]{
		Data:   items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// ListSBOMsByDigest returns SBOMs matching the given container image digest.
func (s *searchService) ListSBOMsByDigest(ctx context.Context, digest string, limit, offset int32) (PagedResult[SBOMSummary], error) {
	q := repository.New(s.pool)

	rows, err := q.ListSBOMsByDigest(ctx, repository.ListSBOMsByDigestParams{
		Digest:    textOrNull(digest),
		RowLimit:  limit,
		RowOffset: offset,
	})
	if err != nil {
		return PagedResult[SBOMSummary]{}, fmt.Errorf("listing sboms by digest: %w", err)
	}

	var total int64
	items := make([]SBOMSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		items = append(items, SBOMSummary{
			ID:             uuidToString(row.ID),
			SerialNumber:   textToPtr(row.SerialNumber),
			SpecVersion:    row.SpecVersion,
			Version:        row.Version,
			ArtifactID:     uuidToPtr(row.ArtifactID),
			SubjectVersion: textToPtr(row.SubjectVersion),
			Digest:         textToPtr(row.Digest),
			CreatedAt:      row.CreatedAt.Time,
		})
	}

	return PagedResult[SBOMSummary]{
		Data:   items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// GetArtifactLicenseSummary returns aggregated license counts for an artifact's latest SBOM.
func (s *searchService) GetArtifactLicenseSummary(ctx context.Context, artifactID pgtype.UUID) ([]LicenseCount, error) {
	q := repository.New(s.pool)

	rows, err := q.LicenseSummaryByArtifact(ctx, artifactID)
	if err != nil {
		return nil, fmt.Errorf("querying license summary: %w", err)
	}

	items := make([]LicenseCount, 0, len(rows))
	for _, row := range rows {
		spdx := textToPtr(row.SpdxID)
		items = append(items, LicenseCount{
			ID:             uuidToString(row.ID),
			SpdxID:         spdx,
			Name:           row.Name,
			URL:            textToPtr(row.Url),
			ComponentCount: row.ComponentCount,
			Category:       classifyLicense(spdx),
		})
	}

	return items, nil
}

// GetSBOMDependencies returns the dependency graph for an SBOM.
func (s *searchService) GetSBOMDependencies(ctx context.Context, sbomID pgtype.UUID) (DependencyGraph, error) {
	q := repository.New(s.pool)

	comps, err := q.ListSBOMComponents(ctx, sbomID)
	if err != nil {
		return DependencyGraph{}, fmt.Errorf("listing components: %w", err)
	}

	deps, err := q.ListDependenciesBySBOM(ctx, sbomID)
	if err != nil {
		return DependencyGraph{}, fmt.Errorf("listing dependencies: %w", err)
	}

	nodes := make([]ComponentSummary, 0, len(comps))
	for _, c := range comps {
		nodes = append(nodes, toComponentSummary(c.ID, sbomID, c.BomRef, c.Type, c.Name, c.GroupName, c.Version, c.Purl))
	}

	edges := make([]DependencyEdge, 0, len(deps))
	for _, d := range deps {
		edges = append(edges, DependencyEdge{From: d.Ref, To: d.DependsOn})
	}

	return DependencyGraph{Nodes: nodes, Edges: edges}, nil
}

// ListSBOMComponents returns all components belonging to an SBOM.
func (s *searchService) ListSBOMComponents(ctx context.Context, sbomID pgtype.UUID) ([]ComponentSummary, error) {
	q := repository.New(s.pool)

	rows, err := q.ListSBOMComponents(ctx, sbomID)
	if err != nil {
		return nil, fmt.Errorf("listing sbom components: %w", err)
	}

	items := make([]ComponentSummary, 0, len(rows))
	for _, c := range rows {
		items = append(items, toComponentSummary(c.ID, sbomID, c.BomRef, c.Type, c.Name, c.GroupName, c.Version, c.Purl))
	}

	return items, nil
}

// ListComponentPurlTypes returns distinct PURL types across all components.
func (s *searchService) ListComponentPurlTypes(ctx context.Context) ([]string, error) {
	q := repository.New(s.pool)
	return q.ListComponentPurlTypes(ctx)
}

// classifyLicense returns a compliance category based on SPDX ID.
func classifyLicense(spdxID *string) string {
	if spdxID == nil {
		return "uncategorized"
	}
	id := *spdxID
	// Copyleft
	copyleft := []string{
		"GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
		"GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
		"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
		"SSPL-1.0", "EUPL-1.2",
	}
	for _, c := range copyleft {
		if id == c {
			return "copyleft"
		}
	}
	// Weak copyleft
	weakCopyleft := []string{
		"LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
		"LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
		"LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
		"MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1",
	}
	for _, c := range weakCopyleft {
		if id == c {
			return "weak-copyleft"
		}
	}
	// Everything else with an SPDX ID is considered permissive
	return "permissive"
}

// Helper functions for pgtype → Go type conversion.

func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
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
