package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

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
		items = append(items, entry)
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

// ListComponentPurlTypes returns distinct PURL types across all components.
func (s *searchService) ListComponentPurlTypes(ctx context.Context) ([]string, error) {
	q := repository.New(s.pool)
	return q.ListComponentPurlTypes(ctx)
}
