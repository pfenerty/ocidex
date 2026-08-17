package service

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Discovery is the public landing-page payload (ocidex-q1z7.2).
//
// There is exactly one of these for the whole instance. Every query behind it is
// scoped to public namespaces in SQL and takes no viewer parameter, so the
// payload is identical for anonymous and signed-in callers alike — which is what
// makes it safe to cache at the edge. Anything personalised belongs on the
// dashboard (ocidex-998g), not here.
type Discovery struct {
	TopArtifacts       []DiscoverArtifact `json:"topArtifacts"`
	RecentArtifacts    []DiscoverRecent   `json:"recentArtifacts"`
	TopVulnerabilities []DiscoverVuln     `json:"topVulnerabilities"`
	LicenseSpread      []DiscoverLicense  `json:"licenseSpread"`
	// GeneratedAt is when the warmer computed this payload. Zero while warming.
	GeneratedAt time.Time `json:"generatedAt"`
	// Warming reports that the aggregates have not been computed yet, so the
	// four sections are empty because nothing is known — not because the catalog
	// is empty. The distinction is the caller's to render.
	Warming bool `json:"warming"`
}

// DiscoverArtifact is one row of the popularity ranking.
type DiscoverArtifact struct {
	ID           string     `json:"id"`
	Type         string     `json:"type"`
	Name         string     `json:"name"`
	Group        *string    `json:"group,omitempty"`
	Purl         *string    `json:"purl,omitempty"`
	UsageCount   int64      `json:"usageCount"`
	VersionCount int64      `json:"versionCount"`
	SbomCount    int64      `json:"sbomCount"`
	LastSeenAt   *time.Time `json:"lastSeenAt,omitempty"`
	// Score is the discovery_score() value the ordering came from. Exposed so a
	// caller can tell a near-tie from a runaway leader rather than reading the
	// ordinal position as a magnitude.
	Score float64 `json:"score"`
}

// DiscoverRecent is one recently updated artifact, with the SBOM that updated it.
type DiscoverRecent struct {
	ArtifactID     string    `json:"artifactId"`
	Type           string    `json:"type"`
	Name           string    `json:"name"`
	Group          *string   `json:"group,omitempty"`
	SbomID         string    `json:"sbomId"`
	SubjectVersion *string   `json:"subjectVersion,omitempty"`
	Digest         *string   `json:"digest,omitempty"`
	Flavor         *string   `json:"flavor,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

// DiscoverVuln is one vulnerability ranked by blast radius across public content.
type DiscoverVuln struct {
	ID          string     `json:"id"`
	CanonicalID string     `json:"canonicalId"`
	Severity    string     `json:"severity"`
	CvssScore   *float32   `json:"cvssScore,omitempty"`
	Summary     *string    `json:"summary,omitempty"`
	PublishedAt *time.Time `json:"publishedAt,omitempty"`
	// AffectedArtifactCount is the headline: distinct public artifacts carrying
	// an affected package. AffectedSbomCount counts every SBOM, so a single image
	// rescanned nightly inflates it — it is kept as the secondary figure because
	// it is what the vulnerability list page reports.
	AffectedArtifactCount int64 `json:"affectedArtifactCount"`
	AffectedSbomCount     int64 `json:"affectedSbomCount"`
}

// DiscoverLicense is one slice of the public license distribution.
type DiscoverLicense struct {
	ID             string  `json:"id"`
	SpdxID         *string `json:"spdxId,omitempty"`
	Name           string  `json:"name"`
	Category       string  `json:"category"`
	ComponentCount int64   `json:"componentCount"`
}

// Section sizes. These are page-shaped rather than API-shaped: the payload is a
// landing page, not a paginated list, and every section has a corresponding full
// list page to link to. Nothing here is caller-tunable, which is part of why the
// response can be identical for everyone.
const (
	discoverTopArtifactLimit = 12
	discoverRecentLimit      = 12
	discoverVulnLimit        = 10
	discoverLicenseLimit     = 12

	// discoverVulnCandidates bounds the cheap first stage of the blast-radius
	// query. Ranking by rollup SBOM count is a good but not exact proxy for
	// ranking by artifact count, so the second stage is given far more candidates
	// than it will return and re-ranks them; too tight a bound here would let a
	// vulnerability in many artifacts but few SBOMs fall off before it is scored.
	discoverVulnCandidates = 200
)

// discoverCacheKey is the single cache slot. Unlike stats, discovery has no
// visibility scope to key on — one payload serves everyone.
const discoverCacheKey = "public"

// GetDiscovery returns the public discovery payload from the TTL cache, which
// the background warmer keeps fresh.
//
// On a miss it returns Warming rather than computing, for the same reason
// GetDashboardStats does: these aggregates rank the whole public catalog and
// cannot finish inside an HTTP timeout, and attempting them on the request path
// holds pool connections that in-flight requests need.
func (s *searchService) GetDiscovery(ctx context.Context) (*Discovery, error) {
	if s.discoverCache == nil {
		return s.WarmDiscovery(ctx)
	}
	if cached := s.discoverCache.get(discoverCacheKey); cached != nil {
		return cached, nil
	}
	return &Discovery{
		TopArtifacts:       []DiscoverArtifact{},
		RecentArtifacts:    []DiscoverRecent{},
		TopVulnerabilities: []DiscoverVuln{},
		LicenseSpread:      []DiscoverLicense{},
		Warming:            true,
	}, nil
}

// WarmDiscovery recomputes the discovery payload and stores it, bypassing the
// cache read so a still-fresh entry is refreshed rather than returned.
func (s *searchService) WarmDiscovery(ctx context.Context) (*Discovery, error) {
	q := repository.New(s.warmHandle())

	var (
		top      []repository.GetDiscoverTopArtifactsRow
		recent   []repository.GetDiscoverRecentArtifactsRow
		vulns    []repository.GetDiscoverTopVulnerabilitiesRow
		licenses []repository.GetDiscoverLicenseSpreadRow
	)

	g, gctx := errgroup.WithContext(ctx)
	// Same bound as the dashboard warm pass, for the same reason: these
	// aggregates scan the same large tables, so widening the fan-out overlaps no
	// I/O and only holds more connections at once.
	g.SetLimit(statsWarmConcurrency)

	g.Go(func() error {
		var err error
		top, err = q.GetDiscoverTopArtifacts(gctx, discoverTopArtifactLimit)
		if err != nil {
			return fmt.Errorf("getting top artifacts: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		recent, err = q.GetDiscoverRecentArtifacts(gctx, discoverRecentLimit)
		if err != nil {
			return fmt.Errorf("getting recent artifacts: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		vulns, err = q.GetDiscoverTopVulnerabilities(gctx, repository.GetDiscoverTopVulnerabilitiesParams{
			CandidateLimit: discoverVulnCandidates,
			RowLimit:       discoverVulnLimit,
		})
		if err != nil {
			return fmt.Errorf("getting top vulnerabilities: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		licenses, err = q.GetDiscoverLicenseSpread(gctx, discoverLicenseLimit)
		if err != nil {
			return fmt.Errorf("getting license spread: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	payload := buildDiscovery(top, recent, vulns, licenses)

	if s.discoverCache != nil {
		s.discoverCache.set(discoverCacheKey, payload)
	}
	return payload, nil
}

// buildDiscovery maps the four raw aggregate row sets into the Discovery DTO.
func buildDiscovery(
	top []repository.GetDiscoverTopArtifactsRow,
	recent []repository.GetDiscoverRecentArtifactsRow,
	vulns []repository.GetDiscoverTopVulnerabilitiesRow,
	licenses []repository.GetDiscoverLicenseSpreadRow,
) *Discovery {
	topItems := make([]DiscoverArtifact, 0, len(top))
	for _, r := range top {
		item := DiscoverArtifact{
			ID:           uuidToString(r.ArtifactID),
			Type:         r.Type,
			Name:         r.Name,
			Group:        textToPtr(r.GroupName),
			Purl:         textToPtr(r.Purl),
			UsageCount:   r.UsageCount,
			VersionCount: r.VersionCount,
			SbomCount:    r.SbomCount,
			Score:        r.Score,
		}
		if r.LastSeenAt.Valid {
			t := r.LastSeenAt.Time
			item.LastSeenAt = &t
		}
		topItems = append(topItems, item)
	}

	recentItems := make([]DiscoverRecent, 0, len(recent))
	for _, r := range recent {
		recentItems = append(recentItems, DiscoverRecent{
			ArtifactID:     uuidToString(r.ArtifactID),
			Type:           r.Type,
			Name:           r.Name,
			Group:          textToPtr(r.GroupName),
			SbomID:         uuidToString(r.SbomID),
			SubjectVersion: textToPtr(r.SubjectVersion),
			Digest:         textToPtr(r.Digest),
			Flavor:         textToPtr(r.Flavor),
			CreatedAt:      r.CreatedAt.Time,
		})
	}

	vulnItems := make([]DiscoverVuln, 0, len(vulns))
	for _, r := range vulns {
		item := DiscoverVuln{
			ID:                    r.ID,
			CanonicalID:           r.CanonicalID,
			Severity:              severityOrUnknown(r.Severity),
			CvssScore:             float4ToPtr(r.CvssScore),
			Summary:               textToPtr(r.Summary),
			AffectedArtifactCount: r.AffectedArtifactCount,
			AffectedSbomCount:     r.AffectedSbomCount,
		}
		if r.PublishedAt.Valid {
			t := r.PublishedAt.Time
			item.PublishedAt = &t
		}
		vulnItems = append(vulnItems, item)
	}

	licenseItems := make([]DiscoverLicense, 0, len(licenses))
	for _, r := range licenses {
		licenseItems = append(licenseItems, DiscoverLicense{
			ID:             uuidToString(r.ID),
			SpdxID:         textToPtr(r.SpdxID),
			Name:           r.Name,
			Category:       r.Category,
			ComponentCount: r.ComponentCount,
		})
	}

	return &Discovery{
		TopArtifacts:       topItems,
		RecentArtifacts:    recentItems,
		TopVulnerabilities: vulnItems,
		LicenseSpread:      licenseItems,
		GeneratedAt:        time.Now().UTC(),
	}
}
