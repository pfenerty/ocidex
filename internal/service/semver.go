package service

import "github.com/Masterminds/semver/v3"

// VersionSortMode selects how a version timeline (versions table, changelog) is
// filtered and ordered.
type VersionSortMode string

const (
	// SortAuto resolves to SortSemver when at least one semver version is
	// present, otherwise SortBuildTime. It is the zero value and the wire
	// default for an unspecified mode.
	SortAuto VersionSortMode = ""
	// SortSemver keeps only semver-parseable versions and orders them by true
	// semantic-version precedence.
	SortSemver VersionSortMode = "semver"
	// SortBuildTime keeps every version and orders by build time (OCI created,
	// falling back to ingestion time).
	SortBuildTime VersionSortMode = "all"
)

// ParseVersionSortMode normalizes an arbitrary wire value to a known mode,
// treating anything unrecognized as SortAuto.
func ParseVersionSortMode(s string) VersionSortMode {
	switch VersionSortMode(s) {
	case SortSemver:
		return SortSemver
	case SortBuildTime:
		return SortBuildTime
	case SortAuto:
		return SortAuto
	default:
		return SortAuto
	}
}

// resolveSortMode collapses SortAuto to a concrete mode: SortSemver when the
// timeline contains at least one semver version, else SortBuildTime.
func resolveSortMode(mode VersionSortMode, hasSemver bool) VersionSortMode {
	if mode == SortAuto {
		if hasSemver {
			return SortSemver
		}
		return SortBuildTime
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
