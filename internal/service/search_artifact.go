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

	// The detail response inherits SufficientSbomCount from ArtifactSummary, and
	// until ocidex-ag4q.33 nothing populated it here — the field was serialized
	// as a permanent 0 while the list endpoint reported the real figure for the
	// same artifact. The band now shows enrichment coverage, so it is counted.
	sufficientCount, err := q.CountSufficientSBOMsByArtifact(ctx, repository.CountSufficientSBOMsByArtifactParams{
		ArtifactID: id,
		UserID:     vis.UserID,
		IsAdmin:    visAdminBool(vis),
	})
	if err != nil {
		return ArtifactDetail{}, fmt.Errorf("counting sufficiently enriched sboms: %w", err)
	}

	versionCount, err := q.CountArtifactVersions(ctx, repository.CountArtifactVersionsParams{
		ArtifactID: id,
		UserID:     vis.UserID,
		IsAdmin:    visAdminBool(vis),
	})
	if err != nil {
		return ArtifactDetail{}, fmt.Errorf("counting versions: %w", err)
	}

	// The watch flag is per-caller, so it is skipped entirely when there is no
	// caller — an anonymous request has no watchlist to be on.
	var watched bool
	if vis.UserID.Valid {
		watched, err = q.IsArtifactWatched(ctx, repository.IsArtifactWatchedParams{
			UserID:     vis.UserID,
			ArtifactID: id,
		})
		if err != nil {
			return ArtifactDetail{}, fmt.Errorf("checking artifact watch: %w", err)
		}
	}

	return ArtifactDetail{
		ArtifactSummary: ArtifactSummary{
			ID:                  uuidToString(row.ID),
			Type:                row.Type,
			Name:                row.Name,
			Group:               textToPtr(row.GroupName),
			SbomCount:           sbomCount,
			SufficientSbomCount: sufficientCount,
			SigningStatus:       row.SigningStatus,
		},
		Purl:         textToPtr(row.Purl),
		Cpe:          textToPtr(row.Cpe),
		CreatedAt:    row.CreatedAt.Time,
		VersionCount: versionCount,
		Watched:      watched,
	}, nil
}

func (s *searchService) ListVersionsByArtifact(ctx context.Context, artifactID pgtype.UUID, limit, offset int32, mode VersionSortMode, colSort VersionColumnSort, vis VisibilityFilter) (ArtifactVersionsPage, error) {
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
	if colSort.Column == VersionSortSeverity {
		sortVersionsBySeverity(all, colSort.Desc)
	}

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
	// A zero total means sbom_vuln_rollup had no row, since the rollup only
	// records SBOMs that have at least one finding. That is "no known
	// vulnerabilities" or "never scanned" indistinguishably, so it maps to a nil
	// summary rather than an all-zero one: the UI has to say "not scanned"
	// (ADR-044), and an all-zero summary would license it to say "clean".
	if total := row.VulnCritical + row.VulnHigh + row.VulnMedium + row.VulnLow + row.VulnUnknown; total > 0 {
		v.Vulns = &VulnSummary{
			Critical: int(row.VulnCritical),
			High:     int(row.VulnHigh),
			Medium:   int(row.VulnMedium),
			Low:      int(row.VulnLow),
			Unknown:  int(row.VulnUnknown),
			Total:    int(total),
		}
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

// VersionSortSeverity is the one column sort the versions list offers beyond
// the mode's own ordering.
const VersionSortSeverity = "severity"

// VersionColumnSort is a column ordering layered on top of a VersionSortMode.
//
// It is deliberately not a third mode: a mode both orders and *filters*
// (SortSemver drops every non-semver version), so folding severity into it
// would silently change which rows the table contains when the user clicked a
// column header.
type VersionColumnSort struct {
	Column string // VersionSortSeverity, or "" for the mode's own ordering
	Desc   bool
}

// ParseVersionColumnSort validates a client-supplied column and direction,
// falling back to the mode's ordering for anything it doesn't recognise.
func ParseVersionColumnSort(column, dir string) VersionColumnSort {
	if column != VersionSortSeverity {
		return VersionColumnSort{}
	}
	return VersionColumnSort{Column: VersionSortSeverity, Desc: dir != "asc"}
}

// sortVersionsBySeverity reorders an already mode-sorted slice worst-first (or
// least-worst-first when ascending). It is stable, so versions of equal severity
// keep the mode's ordering between them.
//
// A version with no summary sorts last in *both* directions. It is unknown, not
// clean; floating it to the top of an ascending sort would present "never
// scanned" as the safest thing on the page, which is the ADR-044 mistake.
func sortVersionsBySeverity(vs []ArtifactVersion, desc bool) {
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := vs[i].Vulns, vs[j].Vulns
		if a == nil || b == nil {
			return b == nil && a != nil
		}
		c := compareSeverityCounts(a, b)
		if desc {
			return c > 0
		}
		return c < 0
	})
}

// compareSeverityCounts orders two summaries worst-first: more criticals wins,
// then more highs, and so on down the scale. Comparing rank by rank rather than
// by a single total keeps one critical ahead of a hundred lows.
func compareSeverityCounts(a, b *VulnSummary) int {
	for _, pair := range [][2]int{
		{a.Critical, b.Critical},
		{a.High, b.High},
		{a.Medium, b.Medium},
		{a.Low, b.Low},
		{a.Unknown, b.Unknown},
	} {
		if pair[0] != pair[1] {
			if pair[0] > pair[1] {
				return 1
			}
			return -1
		}
	}
	return 0
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
		OwnedOnly:         filter.Visibility.ownedFlag(),
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

// ListArtifactVulns returns one page of the artifact's vulnerability list.
//
// Scope note: this is wider than GetArtifactVulnSummary, which counts the
// artifact's newest SBOM only. This list covers the newest SBOM per version,
// because its job is to say *which versions* carry a finding — the question
// /vulnerabilities/{id} sends a reader here with. The band tile and this tab
// therefore report different totals by design; the tab states its scope.
func (s *searchService) ListArtifactVulns(ctx context.Context, artifactID pgtype.UUID, params ArtifactVulnParams, vis VisibilityFilter) (PagedResult[ArtifactVulnEntry], error) {
	q := repository.New(s.db)

	visible, err := q.IsArtifactVisible(ctx, repository.IsArtifactVisibleParams{
		AID:     artifactID,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PagedResult[ArtifactVulnEntry]{}, ErrNotFound
		}
		return PagedResult[ArtifactVulnEntry]{}, fmt.Errorf("checking artifact visibility: %w", err)
	}
	if !visible {
		return PagedResult[ArtifactVulnEntry]{}, ErrNotFound
	}

	limit, offset := clampPage(params.Limit, params.Offset)
	severity := optionalText(params.Severity)
	vuln := optionalText(params.Vuln)

	total, err := q.CountArtifactVulns(ctx, repository.CountArtifactVulnsParams{
		ArtifactID: artifactID,
		UserID:     vis.UserID,
		IsAdmin:    visAdminBool(vis),
		Severity:   severity,
		Vuln:       vuln,
	})
	if err != nil {
		return PagedResult[ArtifactVulnEntry]{}, fmt.Errorf("counting artifact vulns: %w", err)
	}

	sortBy, sortDir := clampSort(params.SortBy, params.SortDir, ArtifactVulnSortKeys)

	rows, err := q.ListArtifactVulns(ctx, repository.ListArtifactVulnsParams{
		ArtifactID: artifactID,
		UserID:     vis.UserID,
		IsAdmin:    visAdminBool(vis),
		Severity:   severity,
		Vuln:       vuln,
		SortBy:     sortBy,
		SortDir:    sortDir,
		Limit:      pgtype.Int4{Int32: limit, Valid: true},
		Offset:     pgtype.Int4{Int32: offset, Valid: true},
	})
	if err != nil {
		return PagedResult[ArtifactVulnEntry]{}, fmt.Errorf("listing artifact vulns: %w", err)
	}

	items := make([]ArtifactVulnEntry, len(rows))
	canonicalIDs := make([]string, len(rows))
	for i, r := range rows {
		canonicalIDs[i] = r.CanonicalID
		items[i] = ArtifactVulnEntry{
			ID:                   r.ID,
			CanonicalID:          r.CanonicalID,
			Severity:             r.Severity.String,
			CvssScore:            float4ToPtr(r.CvssScore),
			Summary:              textToPtr(r.Summary),
			AffectedPackageCount: r.AffectedPackageCount,
			AffectedVersionCount: r.AffectedVersionCount,
			AffectedVersions:     []ArtifactVulnVersion{},
		}
	}

	if len(canonicalIDs) > 0 {
		if err := attachArtifactVulnVersions(ctx, q, artifactID, vis, canonicalIDs, items); err != nil {
			return PagedResult[ArtifactVulnEntry]{}, err
		}
	}

	return PagedResult[ArtifactVulnEntry]{Data: items, Total: total}, nil
}

// attachArtifactVulnVersions fills in the AffectedVersions of one page of
// findings with a single extra query, one per page rather than one per row.
func attachArtifactVulnVersions(ctx context.Context, q *repository.Queries, artifactID pgtype.UUID, vis VisibilityFilter, canonicalIDs []string, items []ArtifactVulnEntry) error {
	rows, err := q.ListArtifactVulnAffectedVersions(ctx, repository.ListArtifactVulnAffectedVersionsParams{
		ArtifactID:   artifactID,
		UserID:       vis.UserID,
		IsAdmin:      visAdminBool(vis),
		CanonicalIds: canonicalIDs,
	})
	if err != nil {
		return fmt.Errorf("listing affected versions: %w", err)
	}

	byCanonical := make(map[string][]ArtifactVulnVersion, len(canonicalIDs))
	for _, r := range rows {
		v := ArtifactVulnVersion{
			Version:              r.VersionKey.String,
			SbomID:               uuidToString(r.SbomID),
			AffectedPackageCount: r.AffectedPackageCount,
			PackageNames:         []string{},
		}
		// package_names arrives as interface{} because it comes out of
		// array_agg, the same way ListSBOMVulnAffectedPackages' fixed_version
		// does.
		if names, ok := r.PackageNames.([]any); ok {
			for _, n := range names {
				if str, ok := n.(string); ok {
					v.PackageNames = append(v.PackageNames, str)
				}
			}
		}
		byCanonical[r.CanonicalID] = append(byCanonical[r.CanonicalID], v)
	}

	for i := range items {
		if versions := byCanonical[items[i].CanonicalID]; versions != nil {
			items[i].AffectedVersions = versions
		}
	}
	return nil
}
