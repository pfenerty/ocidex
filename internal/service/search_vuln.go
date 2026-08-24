package service

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/vuln"
)

// normalizeTopVulnSort clamps the requested sort to the columns
// ListTopVulnerabilities knows how to order by, falling back to the ranking the
// list had before sorting was configurable. The query interpolates neither
// value, so this is about honest defaults rather than injection.
func normalizeTopVulnSort(sort, dir string) (string, string) {
	switch sort {
	case sortBySeverity, "cvss_score", "affected_sbom_count", "affected_purl_count", "published_at", "canonical_id":
	default:
		sort = sortBySeverity
	}
	switch dir {
	case sortAsc, sortDesc:
	default:
		dir = sortDesc
	}
	return sort, dir
}

func (s *searchService) ListTopVulnerabilities(ctx context.Context, filter TopVulnFilter) (PagedResult[TopVulnEntry], error) {
	q := repository.New(s.db)
	isAdmin := visAdminBool(filter.Visibility)

	var severity pgtype.Text
	if filter.Severity != "" {
		severity = pgtype.Text{String: filter.Severity, Valid: true}
	}

	// Trimmed before the emptiness test: a box holding only whitespace is a box
	// the reader has effectively cleared, and matching every id against " "
	// would return the whole list under a filter that looks active.
	var idQuery pgtype.Text
	if q := strings.TrimSpace(filter.IDQuery); q != "" {
		idQuery = pgtype.Text{String: q, Valid: true}
	}

	sortBy, sortDir := normalizeTopVulnSort(filter.Sort, filter.SortDir)

	params := repository.ListTopVulnerabilitiesParams{
		UserID:    filter.Visibility.UserID,
		IsAdmin:   isAdmin,
		OwnedOnly: filter.Visibility.ownedFlag(),
		Severity:  severity,
		IDQuery:   idQuery,
		SortBy:    sortBy,
		SortDir:   sortDir,
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
			CanonicalID:       r.CanonicalID,
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
) (VulnerabilityDetailResult, error) {
	q := repository.New(s.db)

	row, err := q.GetVulnerabilityByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return VulnerabilityDetailResult{}, nil
		}
		return VulnerabilityDetailResult{}, err
	}

	detail := &VulnDetail{
		ID:          row.ID,
		CanonicalID: row.CanonicalID,
		Severity:    severityOrUnknown(row.Severity),
		CvssScore:   float4ToPtr(row.CvssScore),
		CvssVector:  textToPtr(row.CvssVector),
		Summary:     textToPtr(row.Summary),
		Details:     textToPtr(row.Details),
		Aliases:     row.Aliases,
	}
	if row.PublishedAt.Valid {
		t := row.PublishedAt.Time
		detail.PublishedAt = &t
	}
	if row.ModifiedAt.Valid {
		t := row.ModifiedAt.Time
		detail.ModifiedAt = &t
	}

	refRows, err := q.ListVulnerabilityRefs(ctx, id)
	if err != nil {
		return VulnerabilityDetailResult{}, err
	}
	refs := make([]VulnReference, 0, len(refRows))
	for _, r := range refRows {
		refs = append(refs, VulnReference{Type: r.Type, URL: r.Url})
	}
	detail.References = refs

	artifactRows, err := q.ListAffectedArtifactsByVuln(ctx, repository.ListAffectedArtifactsByVulnParams{
		CanonicalID: row.CanonicalID,
		UserID:      vis.UserID,
		IsAdmin:     visAdminBool(vis),
		RowLimit:    pgtype.Int4{Int32: limit, Valid: true},
		RowOffset:   pgtype.Int4{Int32: offset, Valid: true},
	})
	if err != nil {
		return VulnerabilityDetailResult{}, err
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
		CanonicalID: row.CanonicalID,
		UserID:      vis.UserID,
		IsAdmin:     visAdminBool(vis),
	})
	if err != nil {
		return VulnerabilityDetailResult{}, err
	}
	components, componentsTotal := buildAffectedComponents(componentRows)

	namespaceCount, err := q.CountAffectedNamespacesByVuln(ctx, repository.CountAffectedNamespacesByVulnParams{
		CanonicalID: row.CanonicalID,
		UserID:      vis.UserID,
		IsAdmin:     visAdminBool(vis),
	})
	if err != nil {
		return VulnerabilityDetailResult{}, err
	}

	return VulnerabilityDetailResult{
		Detail: detail,
		Artifacts: PagedResult[AffectedArtifact]{
			Data:   items,
			Total:  total,
			Limit:  limit,
			Offset: offset,
		},
		Components: PagedResult[AffectedComponent]{
			Data:   components,
			Total:  componentsTotal,
			Limit:  affectedComponentsLimit,
			Offset: 0,
		},
		NamespaceCount: namespaceCount,
	}, nil
}

// affectedComponentsLimit mirrors the LIMIT in ListAffectedComponentsByVuln.
const affectedComponentsLimit = 100

func buildAffectedComponents(rows []repository.ListAffectedComponentsByVulnRow) ([]AffectedComponent, int64) {
	var total int64
	components := make([]AffectedComponent, 0, len(rows))
	for _, r := range rows {
		if total == 0 {
			total = r.TotalCount
		}
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
	return components, total
}

func severityOrUnknown(t pgtype.Text) string {
	if t.Valid {
		return t.String
	}
	return vuln.SeverityUnknown
}

func float4ToPtr(f pgtype.Float4) *float32 {
	if !f.Valid {
		return nil
	}
	return &f.Float32
}
