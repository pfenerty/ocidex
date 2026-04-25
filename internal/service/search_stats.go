package service

import (
	"context"
	"fmt"

	"github.com/pfenerty/ocidex/internal/repository"
)

// GetDashboardStats returns aggregated metrics for the home dashboard.
func (s *searchService) GetDashboardStats(ctx context.Context, vis VisibilityFilter) (*DashboardStats, error) {
	q := repository.New(s.db)

	visParams := func() (repository.GetSummaryCountsParams, repository.GetLicenseCategoryCountsParams, repository.GetSBOMIngestionTimelineParams, repository.GetPackageGrowthTimelineParams, repository.GetVersionGrowthTimelineParams, repository.GetTopPackagesByVersionCountParams) {
		return repository.GetSummaryCountsParams{UserID: vis.UserID, IsAdmin: visAdminBool(vis)},
			repository.GetLicenseCategoryCountsParams{UserID: vis.UserID, IsAdmin: visAdminBool(vis)},
			repository.GetSBOMIngestionTimelineParams{NumDays: 30, UserID: vis.UserID, IsAdmin: visAdminBool(vis)},
			repository.GetPackageGrowthTimelineParams{UserID: vis.UserID, IsAdmin: visAdminBool(vis)},
			repository.GetVersionGrowthTimelineParams{UserID: vis.UserID, IsAdmin: visAdminBool(vis)},
			repository.GetTopPackagesByVersionCountParams{TopN: 10, UserID: vis.UserID, IsAdmin: visAdminBool(vis)}
	}
	summaryP, catP, timelineP, pkgP, verP, topP := visParams()

	counts, err := q.GetSummaryCounts(ctx, summaryP)
	if err != nil {
		return nil, fmt.Errorf("getting counts: %w", err)
	}

	cats, err := q.GetLicenseCategoryCounts(ctx, catP)
	if err != nil {
		return nil, fmt.Errorf("getting license categories: %w", err)
	}

	timeline, err := q.GetSBOMIngestionTimeline(ctx, timelineP)
	if err != nil {
		return nil, fmt.Errorf("getting ingestion timeline: %w", err)
	}

	pkgGrowth, err := q.GetPackageGrowthTimeline(ctx, pkgP)
	if err != nil {
		return nil, fmt.Errorf("getting package growth timeline: %w", err)
	}

	verGrowth, err := q.GetVersionGrowthTimeline(ctx, verP)
	if err != nil {
		return nil, fmt.Errorf("getting version growth timeline: %w", err)
	}

	topRows, err := q.GetTopPackagesByVersionCount(ctx, topP)
	if err != nil {
		return nil, fmt.Errorf("getting top packages: %w", err)
	}

	catItems := make([]CategoryCount, 0, len(cats))
	for _, c := range cats {
		catItems = append(catItems, CategoryCount{Category: c.Category, ComponentCount: c.ComponentCount})
	}

	toDaily := func(day string, count int64) DailyCount { return DailyCount{Day: day, Count: count} }

	timelineItems := make([]DailyCount, 0, len(timeline))
	for _, t := range timeline {
		timelineItems = append(timelineItems, toDaily(t.Day, t.Count))
	}

	pkgGrowthItems := make([]DailyCount, 0, len(pkgGrowth))
	for _, p := range pkgGrowth {
		pkgGrowthItems = append(pkgGrowthItems, toDaily(p.Day, p.CumulativeCount))
	}

	verGrowthItems := make([]DailyCount, 0, len(verGrowth))
	for _, v := range verGrowth {
		verGrowthItems = append(verGrowthItems, toDaily(v.Day, v.CumulativeCount))
	}

	topItems := make([]PackageSummary, 0, len(topRows))
	for _, p := range topRows {
		topItems = append(topItems, PackageSummary{
			Name:         p.Name,
			Group:        textToPtr(p.GroupName),
			Type:         p.Type,
			VersionCount: p.VersionCount,
			SbomCount:    p.SbomCount,
		})
	}

	return &DashboardStats{
		ArtifactCount:         counts.ArtifactCount,
		SBOMCount:             counts.SbomCount,
		PackageCount:          counts.PackageCount,
		VersionCount:          counts.VersionCount,
		LicenseCount:          counts.LicenseCount,
		LicenseCategories:     catItems,
		IngestionTimeline:     timelineItems,
		PackageGrowthTimeline: pkgGrowthItems,
		VersionGrowthTimeline: verGrowthItems,
		TopPackages:           topItems,
	}, nil
}
