package api

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/pfenerty/ocidex/internal/service"
)

// SearchDistinctComponents handles GET /api/v1/components/distinct.
func (h *Handler) SearchDistinctComponents(ctx context.Context, input *SearchDistinctComponentsInput) (*SearchDistinctComponentsOutput, error) {
	vis := visibilityFilterFromContext(ctx)
	filter := service.ComponentFilter{
		Name:       input.Name,
		Group:      input.Group,
		Type:       input.Type,
		PurlType:   input.PurlType,
		Sort:       input.Sort,
		SortDir:    input.SortDir,
		Limit:      input.Limit,
		Offset:     input.Offset,
		Visibility: vis,
	}

	result, err := h.searchService.SearchDistinctComponents(ctx, filter)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &SearchDistinctComponentsOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = paginationMeta(result)
	return out, nil
}

// GetComponentVersions handles GET /api/v1/components/versions.
func (h *Handler) GetComponentVersions(ctx context.Context, input *GetComponentVersionsInput) (*GetComponentVersionsOutput, error) {
	vis := visibilityFilterFromContext(ctx)
	result, err := h.searchService.GetComponentVersions(ctx, service.ComponentVersionFilter{
		Name:       input.Name,
		Group:      input.Group,
		Version:    input.Version,
		Type:       input.Type,
		Limit:      input.Limit,
		Offset:     input.Offset,
		Visibility: vis,
	})
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetComponentVersionsOutput{}
	out.Body.Versions = result.Data
	out.Body.Pagination = paginationMeta(result.PagedResult)
	out.Body.VersionCount = result.VersionCount
	out.Body.ArtifactCount = result.ArtifactCount
	return out, nil
}

// ListComponentPurlTypes handles GET /api/v1/components/purl-types.
func (h *Handler) ListComponentPurlTypes(ctx context.Context, _ *struct{}) (*ListComponentPurlTypesOutput, error) {
	vis := visibilityFilterFromContext(ctx)
	types, err := h.searchService.ListComponentPurlTypes(ctx, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListComponentPurlTypesOutput{}
	out.Body.Types = types
	return out, nil
}

// ListSBOMComponents handles GET /api/v1/sbom/{id}/components.
func (h *Handler) ListSBOMComponents(ctx context.Context, input *ListSBOMComponentsInput) (*ListSBOMComponentsOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	parts, hasCursor, err := decodeStringCursor(input.Cursor, 3)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	page := service.ComponentPage{Limit: input.Limit, HasCursor: hasCursor}
	if hasCursor {
		page.CursorName, page.CursorGroup, page.CursorID = parts[0], parts[1], parts[2]
	}

	vis := visibilityFilterFromContext(ctx)
	result, err := h.searchService.ListSBOMComponentsPage(ctx, id, page, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListSBOMComponentsOutput{}
	out.Body.Components = result.Data
	out.Body.Pagination = cursorMeta(result.Data, result.HasMore, input.Limit, func(c service.ComponentSummary) string {
		return encodeStringCursor(c.Name, derefOr(c.Group, ""), c.ID)
	})
	return out, nil
}

// ListSBOMVulns handles GET /api/v1/sboms/{id}/vulns: the vulnerability list
// the SBOM page's tile finally has somewhere to send a reader to.
func (h *Handler) ListSBOMVulns(ctx context.Context, in *ListSBOMVulnsInput) (*ListSBOMVulnsOutput, error) {
	id, err := parseUUID(in.ID)
	if err != nil {
		return nil, err
	}

	result, err := h.searchService.ListSBOMVulns(ctx, id, service.SBOMVulnParams{
		Severity: in.Severity,
		SortBy:   in.Sort,
		SortDir:  in.Dir,
		Limit:    in.Limit,
		Offset:   in.Offset,
	}, visibilityFilterFromContext(ctx))
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListSBOMVulnsOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = paginationMeta(result)
	return out, nil
}

// ListSBOMs handles GET /api/v1/sbom.
func (h *Handler) ListSBOMs(ctx context.Context, input *ListSBOMsInput) (*ListSBOMsOutput, error) {
	cur, hasCursor, err := decodeTimeIDCursor(input.Cursor)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	vis := visibilityFilterFromContext(ctx)
	filter := service.SBOMFilter{
		SerialNumber:    input.SerialNumber,
		Digest:          input.Digest,
		Limit:           input.Limit,
		HasCursor:       hasCursor,
		CursorCreatedAt: cur.CreatedAt,
		CursorID:        cur.ID,
		Visibility:      vis,
	}

	result, err := h.searchService.ListSBOMs(ctx, filter)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListSBOMsOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = cursorMeta(result.Data, result.HasMore, input.Limit, func(s service.SBOMSummary) string {
		return encodeTimeIDCursor(s.CreatedAt, s.ID)
	})
	return out, nil
}

// GetSBOMDependencies handles GET /api/v1/sbom/{id}/dependencies.
func (h *Handler) GetSBOMDependencies(ctx context.Context, input *GetSBOMDependenciesInput) (*GetSBOMDependenciesOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	graph, err := h.searchService.GetSBOMDependencies(ctx, id, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetSBOMDependenciesOutput{}
	out.Body = graph
	return out, nil
}

// GetSBOM handles GET /api/v1/sbom/{id}.
func (h *Handler) GetSBOM(ctx context.Context, input *GetSBOMInput) (*GetSBOMOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	includeRaw := input.Include == "raw"
	vis := visibilityFilterFromContext(ctx)

	detail, err := h.searchService.GetSBOM(ctx, id, includeRaw, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetSBOMOutput{}
	out.Body = detail
	return out, nil
}

// ListSBOMDriftHistory handles GET /api/v1/sboms/{id}/drift.
func (h *Handler) ListSBOMDriftHistory(ctx context.Context, in *ListSBOMDriftHistoryInput) (*ListSBOMDriftHistoryOutput, error) {
	id, err := parseUUID(in.ID)
	if err != nil {
		return nil, err
	}
	cur, hasCursor, err := decodeTimeIDCursor(in.Cursor)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	vis := visibilityFilterFromContext(ctx)

	page := service.DriftPage{
		Limit:            in.Limit,
		HasCursor:        hasCursor,
		CursorDetectedAt: cur.CreatedAt,
		CursorID:         cur.ID,
	}
	result, err := h.searchService.ListSBOMDriftHistory(ctx, id, page, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListSBOMDriftHistoryOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = cursorMeta(result.Data, result.HasMore, in.Limit,
		func(d service.ProvenanceDriftSummary) string { return encodeTimeIDCursor(d.DetectedAt, d.ID) })
	return out, nil
}

// SearchComponents handles GET /api/v1/components.
func (h *Handler) SearchComponents(ctx context.Context, input *SearchComponentsInput) (*SearchComponentsOutput, error) {
	// name was required before purl existed; it is now one of two keys, but
	// neither means an unbounded scan of every component row.
	if input.Name == "" && input.Purl == "" {
		return nil, huma.Error400BadRequest("supply either name or purl")
	}

	vis := visibilityFilterFromContext(ctx)
	filter := service.ComponentFilter{
		Name:       input.Name,
		Purl:       input.Purl,
		Group:      input.Group,
		Version:    input.Version,
		Limit:      input.Limit,
		Offset:     input.Offset,
		Visibility: vis,
	}

	result, err := h.searchService.SearchComponents(ctx, filter)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &SearchComponentsOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = paginationMeta(result)
	return out, nil
}

// GetComponent handles GET /api/v1/components/{id}.
func (h *Handler) GetComponent(ctx context.Context, input *GetComponentInput) (*GetComponentOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	detail, err := h.searchService.GetComponent(ctx, id, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetComponentOutput{}
	out.Body = detail
	return out, nil
}

// GetComponentVulns handles GET /api/v1/components/{id}/vulns.
func (h *Handler) GetComponentVulns(ctx context.Context, input *GetComponentVulnsInput) (*GetComponentVulnsOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}
	vis := visibilityFilterFromContext(ctx)
	vulns, err := h.searchService.GetComponentVulns(ctx, id, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &GetComponentVulnsOutput{}
	out.Body.Data = vulns
	return out, nil
}

// ListLicenses handles GET /api/v1/licenses.
func (h *Handler) ListLicenses(ctx context.Context, input *ListLicensesInput) (*ListLicensesOutput, error) {
	vis := visibilityFilterFromContext(ctx)
	filter := service.LicenseFilter{
		SpdxID:     input.SpdxID,
		Name:       input.Name,
		Category:   input.Category,
		Limit:      input.Limit,
		Offset:     input.Offset,
		Visibility: vis,
	}

	result, err := h.searchService.ListLicenses(ctx, filter)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListLicensesOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = paginationMeta(result)
	return out, nil
}

// ListComponentsByLicense handles GET /api/v1/licenses/{id}/components.
func (h *Handler) ListComponentsByLicense(ctx context.Context, input *ListComponentsByLicenseInput) (*ListComponentsByLicenseOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	result, err := h.searchService.ListComponentsByLicense(ctx, id, input.Limit, input.Offset, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListComponentsByLicenseOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = paginationMeta(result)
	return out, nil
}

// ListArtifacts handles GET /api/v1/artifacts.
func (h *Handler) ListArtifacts(ctx context.Context, input *ListArtifactsInput) (*ListArtifactsOutput, error) {
	return h.listArtifacts(ctx, input, visibilityFilterFromContext(ctx))
}

// ListMyArtifacts handles GET /api/v1/users/me/artifacts: the artifacts that
// appear in namespaces the caller owns. Same filters, same keyset pagination,
// same projection as /artifacts — only the row rule differs (ocidex-998g.2).
func (h *Handler) ListMyArtifacts(ctx context.Context, input *ListMyArtifactsInput) (*ListArtifactsOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	return h.listArtifacts(ctx, &input.ListArtifactsInput, ownedFilterFromContext(ctx))
}

func (h *Handler) listArtifacts(ctx context.Context, input *ListArtifactsInput, vis service.VisibilityFilter) (*ListArtifactsOutput, error) {
	parts, hasCursor, err := decodeStringCursor(input.Cursor, 3)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	// Default to showing only sufficiently enriched artifacts; opt out with ?sufficient=false.
	requireSufficient := input.Sufficient != "false"
	filter := service.ArtifactFilter{
		Type:              input.Type,
		Name:              input.Name,
		RequireSufficient: requireSufficient,
		Limit:             input.Limit,
		HasCursor:         hasCursor,
		Visibility:        vis,
	}
	if hasCursor {
		filter.CursorName, filter.CursorType, filter.CursorID = parts[0], parts[1], parts[2]
	}

	result, err := h.searchService.ListArtifacts(ctx, filter)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListArtifactsOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = cursorMeta(result.Data, result.HasMore, input.Limit, func(a service.ArtifactSummary) string {
		return encodeStringCursor(a.Name, a.Type, a.ID)
	})
	return out, nil
}

// GetArtifact handles GET /api/v1/artifacts/{id}.
func (h *Handler) GetArtifact(ctx context.Context, input *GetArtifactInput) (*GetArtifactOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	detail, err := h.searchService.GetArtifact(ctx, id, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetArtifactOutput{}
	out.Body = detail
	return out, nil
}

// ListArtifactSBOMs handles GET /api/v1/artifacts/{id}/sboms.
func (h *Handler) ListArtifactSBOMs(ctx context.Context, input *ListArtifactSBOMsInput) (*ListArtifactSBOMsOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	cur, hasCursor, err := decodeTimeIDCursor(input.Cursor)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	page := service.SBOMByArtifactPage{
		Limit:           input.Limit,
		HasCursor:       hasCursor,
		CursorCreatedAt: cur.CreatedAt,
		CursorID:        cur.ID,
	}

	vis := visibilityFilterFromContext(ctx)
	result, err := h.searchService.ListSBOMsByArtifact(ctx, id, input.SubjectVersion, input.ImageVersion, page, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListArtifactSBOMsOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = cursorMeta(result.Data, result.HasMore, input.Limit, func(s service.SBOMSummary) string {
		return encodeTimeIDCursor(s.CreatedAt, s.ID)
	})
	return out, nil
}

// ListArtifactVersions handles GET /api/v1/artifacts/{id}/versions.
func (h *Handler) ListArtifactVersions(ctx context.Context, input *ListArtifactVersionsInput) (*ListArtifactVersionsOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	result, err := h.searchService.ListVersionsByArtifact(ctx, id, input.Limit, input.Offset, service.ParseVersionSortMode(input.Mode), vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	items := make([]ArtifactVersionSummary, 0, len(result.Data))
	for _, v := range result.Data {
		items = append(items, ArtifactVersionSummary{
			VersionKey:    v.VersionKey,
			SbomID:        v.SbomID,
			SBOMCount:     v.SBOMCount,
			Architectures: v.Architectures,
			ImageVersion:  v.ImageVersion,
			Revision:      v.Revision,
			SourceURL:     v.SourceURL,
			BuildDate:     v.BuildDate,
			CreatedAt:     v.CreatedAt,
			Sufficient:    v.Sufficient,
			SigningStatus: v.SigningStatus,
		})
	}

	out := &ListArtifactVersionsOutput{}
	out.Body.Data = items
	out.Body.Pagination = paginationMeta(result.PagedResult)
	out.Body.HasSemver = result.HasSemver
	out.Body.ResolvedMode = string(result.ResolvedMode)
	return out, nil
}

// DiffSBOMs handles GET /api/v1/sboms/diff?from={id}&to={id}.
func (h *Handler) DiffSBOMs(ctx context.Context, input *DiffSBOMsInput) (*DiffSBOMsOutput, error) {
	fromID, err := parseUUID(input.From)
	if err != nil {
		return nil, err
	}

	toID, err := parseUUID(input.To)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	entry, err := h.searchService.DiffSBOMs(ctx, fromID, toID, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &DiffSBOMsOutput{}
	out.Body = entry
	return out, nil
}

// GetDiffTree handles GET /api/v1/sboms/diff-tree?from={id}&to={id}.
func (h *Handler) GetDiffTree(ctx context.Context, input *DiffTreeInput) (*DiffTreeOutput, error) {
	fromID, err := parseUUID(input.From)
	if err != nil {
		return nil, err
	}
	toID, err := parseUUID(input.To)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	tree, err := h.searchService.DiffSBOMsWithTree(ctx, fromID, toID, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &DiffTreeOutput{}
	out.Body = tree
	return out, nil
}

// GetArtifactLicenseSummary handles GET /api/v1/artifacts/{id}/license-summary.
func (h *Handler) GetArtifactLicenseSummary(ctx context.Context, input *GetArtifactLicenseSummaryInput) (*GetArtifactLicenseSummaryOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	summary, err := h.searchService.GetArtifactLicenseSummary(ctx, id, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetArtifactLicenseSummaryOutput{}
	out.Body.Licenses = summary
	return out, nil
}

// GetArtifactVulnSummary handles GET /api/v1/artifacts/{id}/vuln-summary.
func (h *Handler) GetArtifactVulnSummary(ctx context.Context, input *GetArtifactVulnSummaryInput) (*GetArtifactVulnSummaryOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	summary, err := h.searchService.GetArtifactVulnSummary(ctx, id, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetArtifactVulnSummaryOutput{}
	out.Body.Summary = summary
	return out, nil
}

// GetArtifactUsages handles GET /api/v1/artifacts/{id}/usages.
func (h *Handler) GetArtifactUsages(ctx context.Context, input *GetArtifactUsagesInput) (*GetArtifactUsagesOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	usages, err := h.searchService.GetArtifactUsages(ctx, id, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetArtifactUsagesOutput{}
	out.Body.Usages = usages
	return out, nil
}

// GetArtifactContains handles GET /api/v1/artifacts/{id}/contains.
func (h *Handler) GetArtifactContains(ctx context.Context, input *GetArtifactContainsInput) (*GetArtifactContainsOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	contains, err := h.searchService.GetArtifactContains(ctx, id, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetArtifactContainsOutput{}
	out.Body.Contains = contains
	return out, nil
}

// GetDashboardStats handles GET /api/v1/stats/summary.
func (h *Handler) GetDashboardStats(ctx context.Context, _ *struct{}) (*DashboardStatsOutput, error) {
	vis := visibilityFilterFromContext(ctx)
	stats, err := h.searchService.GetDashboardStats(ctx, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	types := make([]ArtifactTypeCountEntry, 0, len(stats.ArtifactTypes))
	for _, t := range stats.ArtifactTypes {
		types = append(types, ArtifactTypeCountEntry{Type: t.Type, ArtifactCount: t.ArtifactCount})
	}

	cats := make([]CategoryCountEntry, 0, len(stats.LicenseCategories))
	for _, c := range stats.LicenseCategories {
		cats = append(cats, CategoryCountEntry{Category: c.Category, ComponentCount: c.ComponentCount})
	}

	timeline := make([]DailyCountEntry, 0, len(stats.IngestionTimeline))
	for _, t := range stats.IngestionTimeline {
		timeline = append(timeline, DailyCountEntry{Day: t.Day, Count: t.Count})
	}

	pkgs := make([]PackageSummaryEntry, 0, len(stats.TopPackages))
	for _, p := range stats.TopPackages {
		pkgs = append(pkgs, PackageSummaryEntry{
			Name:         p.Name,
			Group:        p.Group,
			Type:         p.Type,
			VersionCount: p.VersionCount,
			SbomCount:    p.SbomCount,
		})
	}

	out := &DashboardStatsOutput{}
	out.Body.ArtifactCount = stats.ArtifactCount
	out.Body.SBOMCount = stats.SBOMCount
	out.Body.PackageCount = stats.PackageCount
	out.Body.VersionCount = stats.VersionCount
	out.Body.LicenseCount = stats.LicenseCount
	pkgGrowth := make([]DailyCountEntry, 0, len(stats.PackageGrowthTimeline))
	for _, p := range stats.PackageGrowthTimeline {
		pkgGrowth = append(pkgGrowth, DailyCountEntry{Day: p.Day, Count: p.Count})
	}

	verGrowth := make([]DailyCountEntry, 0, len(stats.VersionGrowthTimeline))
	for _, v := range stats.VersionGrowthTimeline {
		verGrowth = append(verGrowth, DailyCountEntry{Day: v.Day, Count: v.Count})
	}

	out.Body.ArtifactTypes = types
	out.Body.LicenseCategories = cats
	out.Body.IngestionTimeline = timeline
	out.Body.PackageGrowthTimeline = pkgGrowth
	out.Body.VersionGrowthTimeline = verGrowth
	out.Body.TopPackages = pkgs
	out.Body.Warming = stats.Warming
	out.Body.VulnCount = stats.VulnCount
	out.Body.VulnSeverity = VulnSeverityEntry{
		Critical: stats.VulnSeverity.Critical,
		High:     stats.VulnSeverity.High,
		Medium:   stats.VulnSeverity.Medium,
		Low:      stats.VulnSeverity.Low,
		Unknown:  stats.VulnSeverity.Unknown,
	}
	return out, nil
}

// GetDiscovery handles GET /api/v1/discover.
//
// It takes no visibility filter, deliberately: every query behind the payload is
// scoped to public namespaces in SQL and takes no viewer parameter, so a
// signed-in caller gets the same bytes an anonymous one does. Personalisation
// lives on the dashboard endpoints, not here.
func (h *Handler) GetDiscovery(ctx context.Context, _ *struct{}) (*DiscoveryOutput, error) {
	discovery, err := h.searchService.GetDiscovery(ctx)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &DiscoveryOutput{}
	out.Body.TopArtifacts = discovery.TopArtifacts
	out.Body.RecentArtifacts = discovery.RecentArtifacts
	out.Body.TopVulnerabilities = discovery.TopVulnerabilities
	out.Body.LicenseSpread = discovery.LicenseSpread
	out.Body.Warming = discovery.Warming

	if discovery.Warming {
		// Nothing about a warming response is worth reusing, and caching it would
		// outlive the condition that produced it.
		out.CacheControl = "no-store"
		return out, nil
	}

	out.Body.GeneratedAt = discovery.GeneratedAt.Format(time.RFC3339)
	// The payload is identical for everyone and only changes when the warmer
	// runs, so it is safe to cache publicly. max-age is well under
	// StatsWarmInterval; stale-while-revalidate covers the refresh so no visitor
	// waits on the origin for a landing page.
	out.CacheControl = "public, max-age=60, stale-while-revalidate=300"
	return out, nil
}

// ListTopVulnerabilities handles GET /api/v1/vulns.
func (h *Handler) ListTopVulnerabilities(ctx context.Context, input *ListTopVulnerabilitiesInput) (*ListTopVulnerabilitiesOutput, error) {
	return h.listTopVulnerabilities(ctx, input, visibilityFilterFromContext(ctx))
}

// ListMyVulnerabilities handles GET /api/v1/users/me/vulns: ListTopVulnerabilities
// narrowed to namespaces the caller owns (ocidex-998g.5). The dashboard reads it
// as an exposure figure for what the caller is responsible for, which others'
// public artifacts would inflate without adding anything actionable.
func (h *Handler) ListMyVulnerabilities(ctx context.Context, input *ListMyVulnerabilitiesInput) (*ListTopVulnerabilitiesOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	return h.listTopVulnerabilities(ctx, &input.ListTopVulnerabilitiesInput, ownedFilterFromContext(ctx))
}

func (h *Handler) listTopVulnerabilities(ctx context.Context, input *ListTopVulnerabilitiesInput, vis service.VisibilityFilter) (*ListTopVulnerabilitiesOutput, error) {
	filter := service.TopVulnFilter{
		Limit:      input.Limit,
		Offset:     input.Offset,
		IDQuery:    input.Q,
		Severity:   input.Severity,
		Sort:       input.Sort,
		SortDir:    input.SortDir,
		Visibility: vis,
	}
	result, err := h.searchService.ListTopVulnerabilities(ctx, filter)
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ListTopVulnerabilitiesOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = paginationMeta(result)
	return out, nil
}

// GetVulnerability handles GET /api/v1/vulns/{id}.
func (h *Handler) GetVulnerability(ctx context.Context, input *GetVulnerabilityInput) (*GetVulnerabilityOutput, error) {
	vis := visibilityFilterFromContext(ctx)
	result, err := h.searchService.GetVulnerabilityDetail(ctx, input.ID, input.Limit, input.Offset, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}
	if result.Detail == nil {
		return nil, huma.Error404NotFound("vulnerability not found")
	}
	out := &GetVulnerabilityOutput{}
	out.Body.Vulnerability = *result.Detail
	out.Body.AffectedComponents = result.Components.Data
	out.Body.ComponentsPagination = paginationMeta(result.Components)
	out.Body.AffectedArtifacts = result.Artifacts.Data
	out.Body.Pagination = paginationMeta(result.Artifacts)
	out.Body.NamespaceCount = result.NamespaceCount
	return out, nil
}

// GetArtifactChangelog handles GET /api/v1/artifacts/{id}/changelog.
func (h *Handler) GetArtifactChangelog(ctx context.Context, input *GetArtifactChangelogInput) (*GetArtifactChangelogOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	changelog, err := h.searchService.GetArtifactChangelog(ctx, id, input.SubjectVersion, input.Arch, input.Flavor, service.ParseVersionSortMode(input.Mode), vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetArtifactChangelogOutput{}
	out.Body = changelog
	return out, nil
}
