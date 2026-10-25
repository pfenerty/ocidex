package service

import (
	"testing"

	"github.com/matryer/is"
)

func TestIsSemver(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"1.2.3", true},
		{"v1.2.3", true},
		{"1.2", true},           // Masterminds coerces to 1.2.0
		{"1.0.0-rc.1", true},    // prerelease
		{"1.0.0+build.5", true}, // build metadata
		{"main-abc1234", false},
		{"latest", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			is := is.New(t)
			is.Equal(isSemver(tt.in), tt.want)
		})
	}
}

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.11.0", "1.2.0", 1}, // the ocidex-vez case: 1.11 > 1.2
		{"1.11", "1.2", 1},
		{"2.0.0", "1.9.9", 1},
		{"v1.2.3", "1.2.3", 0},          // v prefix tolerated
		{"1.0.0", "1.0.0-rc.1", 1},      // release > prerelease
		{"1.0.0-rc.2", "1.0.0-rc.1", 1}, // prerelease ordering
		{"1.0.0-alpha", "1.0.0-beta", -1},
		// Non-semver sorts below semver; two non-semver fall back to lexical.
		{"main-b", "1.0.0", -1},
		{"1.0.0", "main-b", 1},
		{"main-b", "main-a", 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			is := is.New(t)
			is.Equal(compareSemver(tt.a, tt.b), tt.want)
		})
	}
}

func TestResolveSortMode(t *testing.T) {
	is := is.New(t)
	is.Equal(resolveSortMode(SortAuto, 3, 3), SortSemver)
	is.Equal(resolveSortMode(SortAuto, 2, 4), SortSemver) // half is enough
	is.Equal(resolveSortMode(SortAuto, 0, 5), SortBuildTime)
	// One tag among 37 branch builds: semver would hide the current build.
	is.Equal(resolveSortMode(SortAuto, 1, 38), SortBuildTime)
	is.Equal(resolveSortMode(SortSemver, 0, 5), SortSemver) // explicit wins
	is.Equal(resolveSortMode(SortBuildTime, 3, 3), SortBuildTime)
}

func TestParseVersionSortMode(t *testing.T) {
	is := is.New(t)
	is.Equal(ParseVersionSortMode("semver"), SortSemver)
	is.Equal(ParseVersionSortMode("all"), SortBuildTime)
	is.Equal(ParseVersionSortMode(""), SortAuto)
	is.Equal(ParseVersionSortMode("bogus"), SortAuto)
}
