package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

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

func (s *searchService) ListVersionsByArtifact(ctx context.Context, artifactID pgtype.UUID, limit, offset int32, mode VersionSortMode, vis VisibilityFilter) (ArtifactVersionsPage, error) {
	q := repository.New(s.db)

	// Semver ordering can't be expressed in SQL, so fetch every distinct version
	// (one row each via the newest_per_version CTE) and sort/paginate in Go.
	rows, err := q.ListArtifactVersions(ctx, repository.ListArtifactVersionsParams{
		ArtifactID: artifactID,
		UserID:     vis.UserID,
		IsAdmin:    visAdminBool(vis),
		RowLimit:   maxVersionsFetch,
		RowOffset:  0,
	})
	if err != nil {
		return ArtifactVersionsPage{}, fmt.Errorf("listing artifact versions: %w", err)
	}

	all := make([]ArtifactVersion, 0, len(rows))
	for _, row := range rows {
		all = append(all, artifactVersionFromRow(row))
	}

	hasSemver := false
	for _, v := range all {
		if isSemver(v.VersionKey) {
			hasSemver = true
			break
		}
	}
	resolved := resolveSortMode(mode, hasSemver)

	if resolved == SortSemver {
		filtered := all[:0:0]
		for _, v := range all {
			if isSemver(v.VersionKey) {
				filtered = append(filtered, v)
			}
		}
		all = filtered
	}
	sortVersions(all, resolved)

	total := int64(len(all))
	page := paginateVersions(all, limit, offset)

	return ArtifactVersionsPage{
		PagedResult: PagedResult[ArtifactVersion]{
			Data:   page,
			Total:  total,
			Limit:  limit,
			Offset: offset,
		},
		HasSemver:    hasSemver,
		ResolvedMode: resolved,
	}, nil
}

// maxVersionsFetch caps the number of distinct versions pulled for in-Go
// sorting; mirrors the changelog's defensive fetch-all cap.
const maxVersionsFetch = 10000

// artifactVersionFromRow maps a ListArtifactVersions row to an ArtifactVersion.
func artifactVersionFromRow(row repository.ListArtifactVersionsRow) ArtifactVersion {
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
	return v
}

// sortVersions orders versions descending. SortSemver uses semantic-version
// precedence (build time breaks ties); otherwise it orders by build time
// (falling back to ingestion time).
func sortVersions(vs []ArtifactVersion, mode VersionSortMode) {
	sort.SliceStable(vs, func(i, j int) bool {
		if mode == SortSemver {
			if cmp := compareSemver(vs[i].VersionKey, vs[j].VersionKey); cmp != 0 {
				return cmp > 0 // descending
			}
		}
		ti, tj := versionEffectiveTime(vs[i]), versionEffectiveTime(vs[j])
		return ti.After(tj) // descending
	})
}

// versionEffectiveTime returns the build time when known, else ingestion time.
func versionEffectiveTime(v ArtifactVersion) time.Time {
	if v.BuildDate != nil {
		return *v.BuildDate
	}
	return v.CreatedAt
}

// paginateVersions applies offset/limit to an already-sorted slice.
func paginateVersions(vs []ArtifactVersion, limit, offset int32) []ArtifactVersion {
	if offset < 0 {
		offset = 0
	}
	start := int(offset)
	if start >= len(vs) {
		return []ArtifactVersion{}
	}
	end := len(vs)
	if limit > 0 && start+int(limit) < end {
		end = start + int(limit)
	}
	return vs[start:end]
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
