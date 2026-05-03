package service

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

func (s *searchService) GetArtifact(ctx context.Context, id pgtype.UUID, vis VisibilityFilter) (ArtifactDetail, error) {
	q := repository.New(s.db)

	// Access check.
	visible, err := q.IsArtifactVisible(ctx, repository.IsArtifactVisibleParams{
		AID:     id,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		return ArtifactDetail{}, fmt.Errorf("checking artifact visibility: %w", err)
	}
	if !visible {
		return ArtifactDetail{}, ErrNotFound
	}

	row, err := q.GetArtifact(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ArtifactDetail{}, ErrNotFound
		}
		return ArtifactDetail{}, fmt.Errorf("getting artifact: %w", err)
	}

	// Get SBOM count via ListSBOMsByArtifact (only visible SBOMs).
	sbomRows, err := q.ListSBOMsByArtifact(ctx, repository.ListSBOMsByArtifactParams{
		ArtifactID:     id,
		SubjectVersion: pgtype.Text{},
		ImageVersion:   pgtype.Text{},
		UserID:         vis.UserID,
		IsAdmin:        visAdminBool(vis),
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

	versionCount, err := q.CountArtifactVersions(ctx, repository.CountArtifactVersionsParams{
		ArtifactID: id,
		UserID:     vis.UserID,
		IsAdmin:    visAdminBool(vis),
	})
	if err != nil {
		return ArtifactDetail{}, fmt.Errorf("counting versions: %w", err)
	}

	return ArtifactDetail{
		ArtifactSummary: ArtifactSummary{
			ID:        uuidToString(row.ID),
			Type:      row.Type,
			Name:      row.Name,
			Group:     textToPtr(row.GroupName),
			SbomCount: sbomCount,
		},
		Purl:         textToPtr(row.Purl),
		Cpe:          textToPtr(row.Cpe),
		CreatedAt:    row.CreatedAt.Time,
		VersionCount: versionCount,
	}, nil
}

func (s *searchService) ListVersionsByArtifact(ctx context.Context, artifactID pgtype.UUID, limit, offset int32, vis VisibilityFilter) (PagedResult[ArtifactVersion], error) {
	q := repository.New(s.db)

	rows, err := q.ListArtifactVersions(ctx, repository.ListArtifactVersionsParams{
		ArtifactID: artifactID,
		UserID:     vis.UserID,
		IsAdmin:    visAdminBool(vis),
		RowLimit:   limit,
		RowOffset:  offset,
	})
	if err != nil {
		return PagedResult[ArtifactVersion]{}, fmt.Errorf("listing artifact versions: %w", err)
	}

	var total int64
	items := make([]ArtifactVersion, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		v := ArtifactVersion{
			VersionKey: row.VersionKey.String,
			SbomID:     uuidToString(row.NewestSbomID),
			Sufficient: row.EnrichmentSufficient,
			CreatedAt:  row.CreatedAt.Time,
		}
		if row.BuildDate.Valid {
			t := row.BuildDate.Time
			v.BuildDate = &t
		}
		if s, ok := row.ImageVersion.(string); ok && s != "" {
			v.ImageVersion = &s
		}
		if s, ok := row.Revision.(string); ok && s != "" {
			v.Revision = &s
		}
		if s, ok := row.SourceUrl.(string); ok && s != "" {
			v.SourceURL = &s
		}
		if arches, ok := row.Architectures.([]interface{}); ok {
			strs := make([]string, 0, len(arches))
			for _, a := range arches {
				if arch, ok := a.(string); ok && arch != "" {
					strs = append(strs, arch)
				}
			}
			sort.Strings(strs)
			v.Architectures = strs
		}
		items = append(items, v)
	}

	return PagedResult[ArtifactVersion]{
		Data:   items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

func (s *searchService) ListArtifacts(ctx context.Context, filter ArtifactFilter) (PagedResult[ArtifactSummary], error) {
	q := repository.New(s.db)

	rows, err := q.ListArtifacts(ctx, repository.ListArtifactsParams{
		Type:              textOrNull(filter.Type),
		Name:              textOrNull(filter.Name),
		RequireSufficient: boolOrNull(filter.RequireSufficient),
		IsAdmin:           visAdminBool(filter.Visibility),
		UserID:            filter.Visibility.UserID,
		RowLimit:          filter.Limit,
		RowOffset:         filter.Offset,
	})
	if err != nil {
		return PagedResult[ArtifactSummary]{}, fmt.Errorf("listing artifacts: %w", err)
	}

	var total int64
	items := make([]ArtifactSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		items = append(items, ArtifactSummary{
			ID:                  uuidToString(row.ID),
			Type:                row.Type,
			Name:                row.Name,
			Group:               textToPtr(row.GroupName),
			SbomCount:           row.SbomCount,
			SufficientSbomCount: row.SufficientSbomCount,
		})
	}

	return PagedResult[ArtifactSummary]{
		Data:   items,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

// GetArtifactLicenseSummary returns aggregated license counts for an artifact's latest SBOM.
func (s *searchService) GetArtifactLicenseSummary(ctx context.Context, artifactID pgtype.UUID, vis VisibilityFilter) ([]LicenseCount, error) {
	q := repository.New(s.db)

	// Access check.
	visible, err := q.IsArtifactVisible(ctx, repository.IsArtifactVisibleParams{
		AID:     artifactID,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		return nil, fmt.Errorf("checking artifact visibility: %w", err)
	}
	if !visible {
		return nil, ErrNotFound
	}

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
