package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

func (s *searchService) SearchComponents(ctx context.Context, filter ComponentFilter) (PagedResult[ComponentSummary], error) {
	q := repository.New(s.db)

	rows, err := q.SearchComponents(ctx, repository.SearchComponentsParams{
		Name:      filter.Name,
		GroupName: textOrNull(filter.Group),
		Version:   textOrNull(filter.Version),
		UserID:    filter.Visibility.UserID,
		IsAdmin:   visAdminBool(filter.Visibility),
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
	q := repository.New(s.db)

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
		UserID:    filter.Visibility.UserID,
		IsAdmin:   visAdminBool(filter.Visibility),
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

func (s *searchService) GetComponentVersions(ctx context.Context, name, group, version, compType string, vis VisibilityFilter) ([]ComponentVersionEntry, error) {
	q := repository.New(s.db)

	rows, err := q.GetComponentVersions(ctx, repository.GetComponentVersionsParams{
		Name:      name,
		GroupName: textOrNull(group),
		Version:   textOrNull(version),
		Type:      textOrNull(compType),
		UserID:    vis.UserID,
		IsAdmin:   visAdminBool(vis),
	})
	if err != nil {
		return nil, fmt.Errorf("getting component versions: %w", err)
	}

	items := make([]ComponentVersionEntry, 0, len(rows))
	var purls []string
	for _, row := range rows {
		entry := ComponentVersionEntry{
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
		}
		if s, ok := row.Architecture.(string); ok && s != "" {
			entry.Architecture = &s
		}
		if p := entry.Purl; p != nil && *p != "" {
			purls = append(purls, *p)
		}
		items = append(items, entry)
	}

	if len(purls) > 0 {
		if err := decorateVersionVulns(ctx, q, purls, items); err != nil {
			return nil, err
		}
	}

	return items, nil
}

func decorateVersionVulns(ctx context.Context, q *repository.Queries, purls []string, items []ComponentVersionEntry) error {
	vulnRows, err := q.ListVulnsByPurls(ctx, purls)
	if err != nil {
		return fmt.Errorf("listing vulns by purls: %w", err)
	}
	type agg struct {
		count                                int
		maxSeverity                          string
		critical, high, medium, low, unknown int
	}
	byPurl := make(map[string]*agg, len(purls))
	for _, r := range vulnRows {
		a := byPurl[r.Purl]
		if a == nil {
			a = &agg{}
			byPurl[r.Purl] = a
		}
		a.count++
		if severityRank(r.Severity.String) > severityRank(a.maxSeverity) {
			a.maxSeverity = r.Severity.String
		}
		switch strings.ToUpper(r.Severity.String) {
		case "CRITICAL":
			a.critical++
		case "HIGH":
			a.high++
		case "MEDIUM":
			a.medium++
		case "LOW":
			a.low++
		default:
			a.unknown++
		}
	}
	for i := range items {
		if items[i].Purl == nil {
			continue
		}
		if a := byPurl[*items[i].Purl]; a != nil {
			items[i].VulnCount = a.count
			items[i].MaxSeverity = a.maxSeverity
			items[i].CriticalCount = a.critical
			items[i].HighCount = a.high
			items[i].MediumCount = a.medium
			items[i].LowCount = a.low
			items[i].UnknownCount = a.unknown
		}
	}
	return nil
}

func (s *searchService) GetComponent(ctx context.Context, id pgtype.UUID, vis VisibilityFilter) (ComponentDetail, error) {
	q := repository.New(s.db)

	row, err := q.GetComponent(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ComponentDetail{}, ErrNotFound
		}
		return ComponentDetail{}, fmt.Errorf("getting component: %w", err)
	}

	// Access check: verify the SBOM this component belongs to is visible.
	visible, err := q.IsSBOMVisible(ctx, repository.IsSBOMVisibleParams{
		ID:      row.SbomID,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		return ComponentDetail{}, fmt.Errorf("checking component visibility: %w", err)
	}
	if !visible {
		return ComponentDetail{}, ErrNotFound
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

	layerID, layer, fromBaseImage, err := s.resolveComponentLayer(ctx, q, row.SbomID, row.LayerID)
	if err != nil {
		return ComponentDetail{}, fmt.Errorf("resolving component layer: %w", err)
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
		FoundBy:          textToPtr(row.FoundBy),
		Confidence:       deriveConfidence(row.FoundBy),
		SourcePackage:    textToPtr(row.SourcePackage),
		LayerID:          layerID,
		Layer:            layer,
		FromBaseImage:    fromBaseImage,
	}, nil
}

// ociLayerMetadata mirrors the subset of oci.Metadata's JSON shape needed to
// resolve layer ordinals. Duplicated (rather than importing
// internal/enrichment/oci) because internal/enrichment imports
// internal/service (for EnrichJobService), so importing any
// internal/enrichment/* package back from internal/service would create an
// import cycle.
type ociLayerMetadata struct {
	BaseName   string `json:"baseName,omitempty"`
	BaseDigest string `json:"baseDigest,omitempty"`
	Layers     []struct {
		Ordinal int    `json:"ordinal"`
		DiffID  string `json:"diffId"`
	} `json:"layers,omitempty"`
}

// resolveComponentLayer resolves a component's layer_id to its ordinal
// position using the sbom's oci-metadata enrichment layer list, and derives
// the FromBaseImage heuristic (see ComponentDetail.FromBaseImage doc).
// Returns zero values, not an error, when layer_id is unset or no
// oci-metadata enrichment succeeded — layer attribution is best-effort.
func (s *searchService) resolveComponentLayer(ctx context.Context, q *repository.Queries, sbomID pgtype.UUID, layerID pgtype.Text) (*string, *int, bool, error) {
	if !layerID.Valid {
		return nil, nil, false, nil
	}
	id := layerID.String

	enr, err := q.GetEnrichment(ctx, repository.GetEnrichmentParams{SbomID: sbomID, EnricherName: "oci-metadata"})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &id, nil, false, nil
		}
		return nil, nil, false, fmt.Errorf("getting oci-metadata enrichment: %w", err)
	}
	if enr.Status != "success" {
		return &id, nil, false, nil
	}

	var meta ociLayerMetadata
	if err := json.Unmarshal(enr.Data, &meta); err != nil {
		slog.Warn("component: skipping malformed oci-metadata enrichment", "sbom_id", sbomID, "err", err)
		return &id, nil, false, nil
	}

	for _, l := range meta.Layers {
		if l.DiffID == id {
			ordinal := l.Ordinal
			hasBase := meta.BaseDigest != "" || meta.BaseName != ""
			return &id, &ordinal, hasBase && ordinal == 0, nil
		}
	}
	return &id, nil, false, nil
}

// deriveConfidence derives a cataloger-confidence signal from found_by at
// read time. Only the binary-cataloger (syft's heuristic binary-signature
// matcher, with no package-manager DB behind it) warrants a warning; all
// other catalogers return nil rather than an invented confidence taxonomy.
func deriveConfidence(foundBy pgtype.Text) *string {
	if foundBy.Valid && foundBy.String == "binary-cataloger" {
		low := "low"
		return &low
	}
	return nil
}

// GetComponentVulns returns all vulnerability findings for the component's purl.
// The visibility check is delegated to GetComponent — if the component is not
// visible the call returns ErrNotFound before any vuln query is made.
func (s *searchService) GetComponentVulns(ctx context.Context, id pgtype.UUID, vis VisibilityFilter) ([]ComponentVulnEntry, error) {
	detail, err := s.GetComponent(ctx, id, vis)
	if err != nil {
		return nil, err
	}
	if detail.Purl == nil || *detail.Purl == "" {
		return nil, nil
	}
	q := repository.New(s.db)
	row, err := q.GetComponent(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("getting component: %w", err)
	}
	rows, err := q.ListVulnsByPurl(ctx, repository.ListVulnsByPurlParams{
		Purl:       *detail.Purl,
		SourcePurl: row.SourcePurl,
	})
	if err != nil {
		return nil, fmt.Errorf("listing component vulns: %w", err)
	}
	out := make([]ComponentVulnEntry, 0, len(rows))
	for _, r := range rows {
		e := ComponentVulnEntry{
			ID:               r.ID,
			CanonicalID:      r.CanonicalID,
			Severity:         r.Severity.String,
			MatchedViaSource: r.MatchedViaSource.Bool,
		}
		if r.CvssScore.Valid {
			v := r.CvssScore.Float32
			e.CvssScore = &v
		}
		if r.Summary.Valid {
			e.Summary = &r.Summary.String
		}
		if s, ok := r.FixedVersion.(string); ok && s != "" {
			e.FixedVersion = &s
		}
		out = append(out, e)
	}
	return out, nil
}

// ListComponentPurlTypes returns distinct PURL types across all visible components.
func (s *searchService) ListComponentPurlTypes(ctx context.Context, vis VisibilityFilter) ([]string, error) {
	q := repository.New(s.db)
	return q.ListComponentPurlTypes(ctx, repository.ListComponentPurlTypesParams{
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
}
