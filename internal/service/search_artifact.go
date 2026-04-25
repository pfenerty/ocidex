package service

import (
	"context"
	"errors"
	"fmt"

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
