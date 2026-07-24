package service

import (
	"testing"
	"time"

	"github.com/matryer/is"
)

func keys(vs []ArtifactVersion) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.VersionKey
	}
	return out
}

func TestSortVersions_SemverDescending(t *testing.T) {
	is := is.New(t)
	// 1.11 must sort above 1.2 (the ocidex-vez regression), newest first.
	vs := []ArtifactVersion{
		{VersionKey: "1.2.0"},
		{VersionKey: "1.11.0"},
		{VersionKey: "1.9.0"},
	}
	sortVersions(vs, SortSemver)
	is.Equal(keys(vs), []string{"1.11.0", "1.9.0", "1.2.0"})
}

func TestSortVersions_BuildTimeDescending(t *testing.T) {
	is := is.New(t)
	older := time.Now().Add(-2 * time.Hour)
	newer := time.Now().Add(-time.Hour)
	// Higher semver but older build must sort last in build-time mode.
	vs := []ArtifactVersion{
		{VersionKey: "2.0.0", BuildDate: &older},
		{VersionKey: "main-abc", BuildDate: &newer},
	}
	sortVersions(vs, SortBuildTime)
	is.Equal(keys(vs), []string{"main-abc", "2.0.0"})
}

func TestSortVersions_BuildTimeFallsBackToIngestion(t *testing.T) {
	is := is.New(t)
	older := time.Now().Add(-2 * time.Hour)
	newer := time.Now().Add(-time.Hour)
	// No BuildDate -> CreatedAt is used as the effective time.
	vs := []ArtifactVersion{
		{VersionKey: "a", CreatedAt: older},
		{VersionKey: "b", CreatedAt: newer},
	}
	sortVersions(vs, SortBuildTime)
	is.Equal(keys(vs), []string{"b", "a"})
}

func TestPaginateVersions(t *testing.T) {
	is := is.New(t)
	vs := []ArtifactVersion{
		{VersionKey: "a"}, {VersionKey: "b"}, {VersionKey: "c"},
	}
	is.Equal(keys(paginateVersions(vs, 2, 0)), []string{"a", "b"})
	is.Equal(keys(paginateVersions(vs, 2, 2)), []string{"c"})
	is.Equal(len(paginateVersions(vs, 2, 5)), 0) // offset past end
	is.Equal(keys(paginateVersions(vs, 0, 0)), []string{"a", "b", "c"}) // limit 0 = all
}
