package service

import (
	"context"
	"testing"
	"time"

	"github.com/matryer/is"
)

// TestGetDiscoveryReportsWarmingOnMiss pins the property the landing page
// depends on: a cache miss must return promptly with Warming set, never fall
// through to computing the aggregates on the request path. A nil db is what
// makes the assertion meaningful — if this ever started querying, it would panic
// rather than quietly pass.
func TestGetDiscoveryReportsWarmingOnMiss(t *testing.T) {
	is := is.New(t)

	s := NewSearchService(nil).(*searchService)

	got, err := s.GetDiscovery(context.Background())
	is.NoErr(err)
	is.True(got.Warming)
	is.Equal(len(got.TopArtifacts), 0)
	is.Equal(len(got.RecentArtifacts), 0)
	is.Equal(len(got.TopVulnerabilities), 0)
	is.Equal(len(got.LicenseSpread), 0)
	is.True(got.GeneratedAt.IsZero())
}

// TestGetDiscoveryServesCachedPayload covers the other side: once the warmer has
// filled the single slot, the request path returns it verbatim and does not
// report warming.
func TestGetDiscoveryServesCachedPayload(t *testing.T) {
	is := is.New(t)

	s := NewSearchService(nil).(*searchService)
	want := &Discovery{
		TopArtifacts: []DiscoverArtifact{{Name: "alpine", UsageCount: 42}},
		GeneratedAt:  time.Unix(1, 0).UTC(),
	}
	s.discoverCache.set(discoverCacheKey, want)

	got, err := s.GetDiscovery(context.Background())
	is.NoErr(err)
	is.Equal(got, want)
	is.True(!got.Warming)
}
