package api

import (
	"context"

	"github.com/pfenerty/ocidex/internal/service"
)

func paginationMeta[T any](r service.PagedResult[T]) PaginationMeta {
	return PaginationMeta{Total: r.Total, Limit: r.Limit, Offset: r.Offset}
}

// visibilityFilterFromContext builds a VisibilityFilter from the authenticated
// user in ctx, if any. Unauthenticated callers get a filter that shows only
// public data.
func visibilityFilterFromContext(ctx context.Context) service.VisibilityFilter {
	user, ok := UserFromContext(ctx)
	if !ok {
		return service.VisibilityFilter{}
	}
	return service.VisibilityFilter{
		IsAdmin: user.Role == roleAdmin,
		UserID:  user.ID,
	}
}

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
	versions, err := h.searchService.GetComponentVersions(ctx, input.Name, input.Group, input.Version, input.Type, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetComponentVersionsOutput{}
	out.Body.Versions = versions
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

	vis := visibilityFilterFromContext(ctx)
	components, err := h.searchService.ListSBOMComponents(ctx, id, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListSBOMComponentsOutput{}
	out.Body.Components = components
	return out, nil
}

// ListSBOMs handles GET /api/v1/sbom.
func (h *Handler) ListSBOMs(ctx context.Context, input *ListSBOMsInput) (*ListSBOMsOutput, error) {
	vis := visibilityFilterFromContext(ctx)
	filter := service.SBOMFilter{
		SerialNumber: input.SerialNumber,
		Digest:       input.Digest,
		Limit:        input.Limit,
		Offset:       input.Offset,
		Visibility:   vis,
	}

	result, err := h.searchService.ListSBOMs(ctx, filter)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListSBOMsOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = paginationMeta(result)
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

// SearchComponents handles GET /api/v1/components.
func (h *Handler) SearchComponents(ctx context.Context, input *SearchComponentsInput) (*SearchComponentsOutput, error) {
	vis := visibilityFilterFromContext(ctx)
	filter := service.ComponentFilter{
		Name:       input.Name,
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
	// Default to showing only sufficiently enriched artifacts; opt out with ?sufficient=false.
	requireSufficient := input.Sufficient != "false"
	filter := service.ArtifactFilter{
		Type:              input.Type,
		Name:              input.Name,
		RequireSufficient: requireSufficient,
		Limit:             input.Limit,
		Offset:            input.Offset,
		Visibility:        visibilityFilterFromContext(ctx),
	}

	result, err := h.searchService.ListArtifacts(ctx, filter)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListArtifactsOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = paginationMeta(result)
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

	vis := visibilityFilterFromContext(ctx)
	result, err := h.searchService.ListSBOMsByArtifact(ctx, id, input.SubjectVersion, input.ImageVersion, input.Limit, input.Offset, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListArtifactSBOMsOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = paginationMeta(result)
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

// GetDashboardStats handles GET /api/v1/stats/summary.
func (h *Handler) GetDashboardStats(ctx context.Context, _ *struct{}) (*DashboardStatsOutput, error) {
	vis := visibilityFilterFromContext(ctx)
	stats, err := h.searchService.GetDashboardStats(ctx, vis)
	if err != nil {
		return nil, mapServiceError(err)
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

	out.Body.LicenseCategories = cats
	out.Body.IngestionTimeline = timeline
	out.Body.PackageGrowthTimeline = pkgGrowth
	out.Body.VersionGrowthTimeline = verGrowth
	out.Body.TopPackages = pkgs
	return out, nil
}

// GetArtifactChangelog handles GET /api/v1/artifacts/{id}/changelog.
func (h *Handler) GetArtifactChangelog(ctx context.Context, input *GetArtifactChangelogInput) (*GetArtifactChangelogOutput, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	changelog, err := h.searchService.GetArtifactChangelog(ctx, id, input.SubjectVersion, input.Arch, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetArtifactChangelogOutput{}
	out.Body = changelog
	return out, nil
}
