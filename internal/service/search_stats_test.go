package service

import (
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// The dashboard renders the type breakdown next to the total artifact count, so
// the rows must survive the mapping in the order the query ranked them.
func TestBuildDashboardStatsMapsArtifactTypes(t *testing.T) {
	is := is.New(t)

	stats := buildDashboardStats(
		repository.GetSummaryCountsRow{ArtifactCount: 38},
		[]repository.GetArtifactTypeCountsRow{
			{Type: "container", ArtifactCount: 24},
			{Type: "library", ArtifactCount: 9},
			{Type: "application", ArtifactCount: 5},
		},
		nil, nil, nil, nil, nil, repository.GetVulnStatsRow{},
	)

	is.Equal(len(stats.ArtifactTypes), 3)
	is.Equal(stats.ArtifactTypes[0], ArtifactTypeCount{Type: "container", ArtifactCount: 24})
	is.Equal(stats.ArtifactTypes[2], ArtifactTypeCount{Type: "application", ArtifactCount: 5})

	var sum int64
	for _, t := range stats.ArtifactTypes {
		sum += t.ArtifactCount
	}
	is.Equal(sum, stats.ArtifactCount)
}

// An empty catalog must serialize as [] rather than null: the frontend iterates
// the field, and a null would make the chip row a runtime error rather than an
// absent element.
func TestBuildDashboardStatsEmptyArtifactTypesIsNonNil(t *testing.T) {
	is := is.New(t)

	stats := buildDashboardStats(
		repository.GetSummaryCountsRow{},
		nil, nil, nil, nil, nil, nil, repository.GetVulnStatsRow{},
	)

	is.Equal(len(stats.ArtifactTypes), 0)
	is.True(stats.ArtifactTypes != nil)
}
