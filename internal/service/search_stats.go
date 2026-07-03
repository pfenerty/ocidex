package service

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/pfenerty/ocidex/internal/repository"
)

// GetDashboardStats returns aggregated metrics for the home dashboard. Results
// are TTL-cached per visibility scope because the underlying aggregates scan the
// whole component table; recomputing on every dashboard load does not scale.
func (s *searchService) GetDashboardStats(ctx context.Context, vis VisibilityFilter) (*DashboardStats, error) {
	cacheKey := statsCacheKey(vis)
	if s.statsCache != nil {
		if cached := s.statsCache.get(cacheKey); cached != nil {
			return cached, nil
		}
	}

	q := repository.New(s.db)
	isAdmin := visAdminBool(vis)

	summaryP := repository.GetSummaryCountsParams{UserID: vis.UserID, IsAdmin: isAdmin}
	catP := repository.GetLicenseCategoryCountsParams{UserID: vis.UserID, IsAdmin: isAdmin}
	timelineP := repository.GetSBOMIngestionTimelineParams{NumDays: 30, UserID: vis.UserID, IsAdmin: isAdmin}
	pkgP := repository.GetPackageGrowthTimelineParams{UserID: vis.UserID, IsAdmin: isAdmin}
	verP := repository.GetVersionGrowthTimelineParams{UserID: vis.UserID, IsAdmin: isAdmin}
	topP := repository.GetTopPackagesByVersionCountParams{TopN: 10, UserID: vis.UserID, IsAdmin: isAdmin}
	vulnP := repository.GetVulnStatsParams{UserID: vis.UserID, IsAdmin: isAdmin}

	var (
		counts    repository.GetSummaryCountsRow
		cats      []repository.GetLicenseCategoryCountsRow
		timeline  []repository.GetSBOMIngestionTimelineRow
		pkgGrowth []repository.GetPackageGrowthTimelineRow
		verGrowth []repository.GetVersionGrowthTimelineRow
		topRows   []repository.GetTopPackagesByVersionCountRow
		vulnStats repository.GetVulnStatsRow
	)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		var err error
		counts, err = q.GetSummaryCounts(gctx, summaryP)
		if err != nil {
			return fmt.Errorf("getting counts: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		cats, err = q.GetLicenseCategoryCounts(gctx, catP)
		if err != nil {
			return fmt.Errorf("getting license categories: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		timeline, err = q.GetSBOMIngestionTimeline(gctx, timelineP)
		if err != nil {
			return fmt.Errorf("getting ingestion timeline: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		pkgGrowth, err = q.GetPackageGrowthTimeline(gctx, pkgP)
		if err != nil {
			return fmt.Errorf("getting package growth timeline: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		verGrowth, err = q.GetVersionGrowthTimeline(gctx, verP)
		if err != nil {
			return fmt.Errorf("getting version growth timeline: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		topRows, err = q.GetTopPackagesByVersionCount(gctx, topP)
		if err != nil {
			return fmt.Errorf("getting top packages: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		vulnStats, err = q.GetVulnStats(gctx, vulnP)
		if err != nil {
			return fmt.Errorf("getting vuln stats: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	stats := buildDashboardStats(counts, cats, timeline, pkgGrowth, verGrowth, topRows, vulnStats)

	if s.statsCache != nil {
		s.statsCache.set(cacheKey, stats)
	}

	return stats, nil
}

// buildDashboardStats maps the raw aggregate rows into the DashboardStats DTO.
func buildDashboardStats(
	counts repository.GetSummaryCountsRow,
	cats []repository.GetLicenseCategoryCountsRow,
	timeline []repository.GetSBOMIngestionTimelineRow,
	pkgGrowth []repository.GetPackageGrowthTimelineRow,
	verGrowth []repository.GetVersionGrowthTimelineRow,
	topRows []repository.GetTopPackagesByVersionCountRow,
	vulnStats repository.GetVulnStatsRow,
) *DashboardStats {
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
		VulnCount:             vulnStats.TotalVulns,
		VulnSeverity: VulnSeverityBreakdown{
			Critical: vulnStats.CriticalCount,
			High:     vulnStats.HighCount,
			Medium:   vulnStats.MediumCount,
			Low:      vulnStats.LowCount,
			Unknown:  vulnStats.UnknownCount,
		},
	}
}
