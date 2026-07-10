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

	// Count visible SBOMs for this artifact.
	sbomCount, err := q.CountSBOMsByArtifact(ctx, repository.CountSBOMsByArtifactParams{
		ArtifactID: id,
		UserID:     vis.UserID,
		IsAdmin:    visAdminBool(vis),
	})
	if err != nil {
		return ArtifactDetail{}, fmt.Errorf("counting sboms: %w", err)
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
			ID:            uuidToString(row.ID),
			Type:          row.Type,
			Name:          row.Name,
			Group:         textToPtr(row.GroupName),
			SbomCount:     sbomCount,
			SigningStatus: row.SigningStatus,
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
			VersionKey:    row.VersionKey.String,
			SbomID:        uuidToString(row.NewestSbomID),
			SBOMCount:     row.SbomCount,
			Sufficient:    row.EnrichmentSufficient,
			CreatedAt:     row.CreatedAt.Time,
			SigningStatus: row.SigningStatus,
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

func (s *searchService) ListArtifacts(ctx context.Context, filter ArtifactFilter) (CursorPage[ArtifactSummary], error) {
	q := repository.New(s.db)

	// Fetch one extra row to detect whether a further page exists.
	rows, err := q.ListArtifacts(ctx, repository.ListArtifactsParams{
		Type:              textOrNull(filter.Type),
		Name:              textOrNull(filter.Name),
		RequireSufficient: boolOrNull(filter.RequireSufficient),
		IsAdmin:           visAdminBool(filter.Visibility),
		UserID:            filter.Visibility.UserID,
		HasCursor:         pgtype.Bool{Bool: filter.HasCursor, Valid: true},
		CursorName:        textOrNull(filter.CursorName),
		CursorType:        textOrNull(filter.CursorType),
		CursorID:          uuidOrNull(filter.CursorID),
		RowLimit:          filter.Limit + 1,
	})
	if err != nil {
		return CursorPage[ArtifactSummary]{}, fmt.Errorf("listing artifacts: %w", err)
	}

	hasMore := len(rows) > int(filter.Limit)
	if hasMore {
		rows = rows[:filter.Limit]
	}

	items := make([]ArtifactSummary, 0, len(rows))
	for _, row := range rows {
		items = append(items, ArtifactSummary{
			ID:                  uuidToString(row.ID),
			Type:                row.Type,
			Name:                row.Name,
			Group:               textToPtr(row.GroupName),
			SbomCount:           row.SbomCount,
			SufficientSbomCount: row.SufficientSbomCount,
			SigningStatus:       row.SigningStatus,
		})
	}

	return CursorPage[ArtifactSummary]{Data: items, HasMore: hasMore}, nil
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

// GetArtifactVulnSummary returns per-severity vuln counts for an artifact's latest SBOM.
func (s *searchService) GetArtifactVulnSummary(ctx context.Context, artifactID pgtype.UUID, vis VisibilityFilter) (*VulnSummary, error) {
	q := repository.New(s.db)

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

	rows, err := q.GetArtifactVulnSummary(ctx, artifactID)
	if err != nil {
		return nil, fmt.Errorf("querying artifact vuln summary: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	var vs VulnSummary
	for _, r := range rows {
		n := int(r.Count)
		vs.Total += n
		switch r.Severity.String {
		case sevCritical:
			vs.Critical += n
		case sevHigh:
			vs.High += n
		case sevMedium:
			vs.Medium += n
		case sevLow:
			vs.Low += n
		default:
			vs.Unknown += n
		}
	}
	if vs.Total == 0 {
		return nil, nil
	}
	return &vs, nil
}
