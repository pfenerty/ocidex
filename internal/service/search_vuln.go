package service

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pfenerty/ocidex/internal/repository"
)

func (s *searchService) ListTopVulnerabilities(ctx context.Context, filter TopVulnFilter) (PagedResult[TopVulnEntry], error) {
	q := repository.New(s.db)
	isAdmin := visAdminBool(filter.Visibility)

	var severity pgtype.Text
	if filter.Severity != "" {
		severity = pgtype.Text{String: filter.Severity, Valid: true}
	}

	params := repository.ListTopVulnerabilitiesParams{
		UserID:    filter.Visibility.UserID,
		IsAdmin:   isAdmin,
		Severity:  severity,
		RowLimit:  pgtype.Int4{Int32: filter.Limit, Valid: true},
		RowOffset: pgtype.Int4{Int32: filter.Offset, Valid: true},
	}

	rows, err := q.ListTopVulnerabilities(ctx, params)
	if err != nil {
		return PagedResult[TopVulnEntry]{}, err
	}

	entries := make([]TopVulnEntry, 0, len(rows))
	var total int64
	for _, r := range rows {
		if total == 0 {
			total = r.TotalCount
		}
		entry := TopVulnEntry{
			ID:                r.ID,
			Severity:          severityOrUnknown(r.Severity),
			CvssScore:         float4ToPtr(r.CvssScore),
			Summary:           textToPtr(r.Summary),
			Aliases:           r.Aliases,
			AffectedSbomCount: r.AffectedSbomCount,
			AffectedPurlCount: r.AffectedPurlCount,
		}
		if r.PublishedAt.Valid {
			t := r.PublishedAt.Time
			entry.PublishedAt = &t
		}
		entries = append(entries, entry)
	}

	return PagedResult[TopVulnEntry]{
		Data:   entries,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (s *searchService) GetVulnerabilityDetail(
	ctx context.Context, id string,
	limit, offset int32, vis VisibilityFilter,
) (*VulnDetail, PagedResult[AffectedArtifact], []AffectedComponent, error) {
	q := repository.New(s.db)

	row, err := q.GetVulnerabilityByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, PagedResult[AffectedArtifact]{}, nil, nil
		}
		return nil, PagedResult[AffectedArtifact]{}, nil, err
	}

	detail := &VulnDetail{
		ID:        row.ID,
		Severity:  severityOrUnknown(row.Severity),
		CvssScore: float4ToPtr(row.CvssScore),
		Summary:   textToPtr(row.Summary),
		Details:   textToPtr(row.Details),
		Aliases:   row.Aliases,
	}
	if row.PublishedAt.Valid {
		t := row.PublishedAt.Time
		detail.PublishedAt = &t
	}
	if row.ModifiedAt.Valid {
		t := row.ModifiedAt.Time
		detail.ModifiedAt = &t
	}

	artifactRows, err := q.ListAffectedArtifactsByVuln(ctx, repository.ListAffectedArtifactsByVulnParams{
		VulnerabilityID: id,
		UserID:          vis.UserID,
		IsAdmin:         visAdminBool(vis),
		RowLimit:        pgtype.Int4{Int32: limit, Valid: true},
		RowOffset:       pgtype.Int4{Int32: offset, Valid: true},
	})
	if err != nil {
		return nil, PagedResult[AffectedArtifact]{}, nil, err
	}

	var total int64
	items := make([]AffectedArtifact, 0, len(artifactRows))
	for _, r := range artifactRows {
		if total == 0 {
			total = r.TotalCount
		}
		a := AffectedArtifact{
			ID:                r.ID,
			Name:              r.Name,
			AffectedSbomCount: r.AffectedSbomCount,
			AffectedPurlCount: r.AffectedPurlCount,
		}
		if r.GroupName.Valid {
			a.Group = &r.GroupName.String
		}
		items = append(items, a)
	}

	componentRows, err := q.ListAffectedComponentsByVuln(ctx, repository.ListAffectedComponentsByVulnParams{
		VulnerabilityID: id,
		UserID:          vis.UserID,
		IsAdmin:         visAdminBool(vis),
	})
	if err != nil {
		return nil, PagedResult[AffectedArtifact]{}, nil, err
	}

	components := make([]AffectedComponent, 0, len(componentRows))
	for _, r := range componentRows {
		c := AffectedComponent{
			Name:                 r.Name,
			AffectedVersionCount: r.AffectedVersionCount,
		}
		if r.GroupName.Valid {
			c.Group = &r.GroupName.String
		}
		if r.FixedVersion.Valid {
			c.FixedVersion = &r.FixedVersion.String
		}
		components = append(components, c)
	}

	return detail, PagedResult[AffectedArtifact]{
		Data:   items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, components, nil
}

func severityOrUnknown(t pgtype.Text) string {
	if t.Valid {
		return t.String
	}
	return "UNKNOWN"
}

func float4ToPtr(f pgtype.Float4) *float32 {
	if !f.Valid {
		return nil
	}
	return &f.Float32
}
