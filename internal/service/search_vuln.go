package service

import (
	"context"

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
