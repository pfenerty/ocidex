package service

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/pfenerty/ocidex/internal/repository"
)

// statsWarmConcurrency caps how many dashboard aggregates run at once. It must
// stay at or below the background pool's MaxConns so a warm pass can never
// consume connections the HTTP handlers are waiting on.
const statsWarmConcurrency = 2

// normalizeStatsScope reduces a viewer's filter to the coarsest equivalent one.
//
// sbom_visible() grants a row when the viewer is an admin, the registry is
// public, or the viewer owns it. So an authenticated non-admin who owns no
// private registry sees precisely the public set — identical to an anonymous
// viewer — and is served from the shared anonymous scope, which the background
// warmer keeps fresh. Without this, every logged-in user got a private "u:<id>"
// scope that the warmer cannot enumerate, so their dashboard always missed the
// cache, always took the multi-minute path, and always died at the HTTP
// timeout before it could write the entry back.
func (s *searchService) normalizeStatsScope(ctx context.Context, vis VisibilityFilter) VisibilityFilter {
	if vis.IsAdmin || !vis.UserID.Valid {
		return vis
	}
	n, err := repository.New(s.db).CountOwnedPrivateRegistries(ctx, vis.UserID)
	if err != nil || n > 0 {
		// On error keep the viewer's own scope: over-narrowing the cache key is
		// a performance loss, but widening it on a failed check could serve
		// them another viewer's private data.
		return vis
	}
	return VisibilityFilter{}
}

// GetDashboardStats returns aggregated metrics for the home dashboard from the
// TTL cache, which the background StatsWarmer keeps fresh.
//
// On a miss it returns empty stats rather than computing them. The aggregates
// scan the whole component table and take minutes; running them on the request
// path cannot succeed inside the HTTP timeout, and every attempt occupies pool
// connections that in-flight requests need. Callers render the loading state
// and retry, by which time the warmer has filled the entry.
func (s *searchService) GetDashboardStats(ctx context.Context, vis VisibilityFilter) (*DashboardStats, error) {
	if s.statsCache == nil {
		return s.WarmDashboardStats(ctx, vis)
	}
	if cached := s.statsCache.get(statsCacheKey(s.normalizeStatsScope(ctx, vis))); cached != nil {
		return cached, nil
	}
	return &DashboardStats{Warming: true}, nil
}

// WarmDashboardStats recomputes dashboard stats for a visibility scope and
// stores them in the cache, bypassing the cache read. The background warmer
// calls this so entries are refreshed before they expire — going through
// GetDashboardStats would find the entry still fresh and never recompute it.
func (s *searchService) WarmDashboardStats(ctx context.Context, vis VisibilityFilter) (*DashboardStats, error) {
	q := repository.New(s.warmHandle())
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
	// Bound the fan-out. These seven aggregates all scan the same handful of
	// large tables, so running them wide does not overlap I/O with anything —
	// it just holds seven pool connections and seven Postgres backends at once,
	// starving request traffic on a database with a single CPU core.
	g.SetLimit(statsWarmConcurrency)

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
		s.statsCache.set(statsCacheKey(vis), stats)
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
