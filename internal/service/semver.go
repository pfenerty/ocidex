package service

import (
	"regexp"
	"strconv"

	"github.com/Masterminds/semver/v3"
)

// VersionSortMode selects how a version timeline (versions table, changelog) is
// filtered and ordered.
type VersionSortMode string

const (
	// SortAuto resolves to SortSemver when at least one semver version is
	// present, otherwise SortAll. It is the zero value and the wire
	// default for an unspecified mode.
	SortAuto VersionSortMode = ""
	// SortSemver keeps only semver-parseable versions and orders them by true
	// semantic-version precedence.
	SortSemver VersionSortMode = "semver"
	// SortAll keeps every version and orders by version parts
	// (compareVersionLine), with build time only breaking ties. Build time
	// alone listed a version backfilled later above its successor.
	SortAll VersionSortMode = "all"
)

// ParseVersionSortMode normalizes an arbitrary wire value to a known mode,
// treating anything unrecognized as SortAuto.
func ParseVersionSortMode(s string) VersionSortMode {
	switch VersionSortMode(s) {
	case SortSemver:
		return SortSemver
	case SortAll:
		return SortAll
	case SortAuto:
		return SortAuto
	default:
		return SortAuto
	}
}

// resolveSortMode collapses SortAuto to a concrete mode: SortSemver when
// semver versions make up at least half of the timeline's distinct versions,
// else SortAll. Semver mode hides every other version, so "any semver
// at all" opened an artifact of 37 branch builds and one v0.2.0 tag on a
// one-row list.
func resolveSortMode(mode VersionSortMode, semverCount, total int) VersionSortMode {
	if mode == SortAuto {
		if semverCount > 0 && semverCount*2 >= total {
			return SortSemver
		}
		return SortAll
	}
	return mode
}

// isSemver reports whether s parses as a semantic version. A leading "v" is
// tolerated (Masterminds normalizes it), as are partial versions like "1.2".
func isSemver(s string) bool {
	_, err := semver.NewVersion(s)
	return err == nil
}

// compareSemver orders two version strings by semantic-version precedence,
// returning -1, 0, or 1. It correctly handles prerelease ordering
// (1.0.0 > 1.0.0-rc.1), build metadata, and a leading "v". Values that do not
// parse as semver sort below any that do; two non-semver values fall back to a
// lexical comparison so the ordering is deterministic.
func compareSemver(a, b string) int {
	va, errA := semver.NewVersion(a)
	vb, errB := semver.NewVersion(b)
	switch {
	case errA == nil && errB == nil:
		return va.Compare(vb)
	case errA == nil:
		return 1
	case errB == nil:
		return -1
	default:
		switch {
		case a < b:
			return -1
		case a > b:
			return 1
		default:
			return 0
		}
	}
}

// versionPartsRe captures up to three leading numeric parts, the way the sbom
// table's generated version_major/minor/patch columns read subject_version.
var versionPartsRe = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

// versionParts returns major, minor and patch as the sbom generated columns
// do: -1 where a part is absent, and a run longer than nine digits (a SHA
// prefix, not a version) ends the parse there.
func versionParts(key string) [3]int {
	parts := [3]int{-1, -1, -1}
	m := versionPartsRe.FindStringSubmatch(key)
	if m == nil {
		return parts
	}
	for i := 0; i < 3; i++ {
		// A part followed by more digits than the capture took cannot happen:
		// \d+ is greedy. Only the length cap needs checking.
		if m[i+1] == "" || len(m[i+1]) > 9 {
			break
		}
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			break
		}
		parts[i] = n
	}
	return parts
}

// compareVersionLine orders two version keys the way the database orders a
// version line: by major, minor and patch (an absent part below any present
// one), then a release above its prereleases, then the plain line above its
// variants and variants by name. It returns 0 when those all tie, leaving
// time to the caller.
func compareVersionLine(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] > pb[i] {
				return 1
			}
			return -1
		}
	}
	va, preA := VersionLine(a)
	vb, preB := VersionLine(b)
	switch {
	case preA != preB:
		if preA {
			return -1
		}
		return 1
	case (va == "") != (vb == ""):
		if va == "" {
			return 1
		}
		return -1
	case va != vb:
		// Descending sort, so the alphabetically first variant ranks higher.
		if va < vb {
			return 1
		}
		return -1
	}
	return 0
}
