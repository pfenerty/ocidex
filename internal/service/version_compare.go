// Version ordering and change classification: the Debian version algorithm
// for distro packages, semver elsewhere, and the upgrade/downgrade verdict
// both feed. Split out of changelog.go.

package service

import (
	"strconv"
	"strings"
)

// debCharOrd returns the deb-policy ordering value for a byte (zero byte = end of string).
// Tilde < end-of-string < letters < non-letters (per Debian policy manual §5.6.12).
func debCharOrd(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0:
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

// debReadAlpha consumes a non-digit prefix from s[i:] and returns the new index.
func debReadAlpha(s string, i int) ([]byte, int) {
	start := i
	for i < len(s) && (s[i] < '0' || s[i] > '9') {
		i++
	}
	return []byte(s[start:i]), i
}

// debReadDigit consumes a digit prefix from s[i:] and returns the integer value and new index.
func debReadDigit(s string, i int) (int, int) {
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	v, _ := strconv.Atoi(s[start:i])
	return v, i
}

// debCmpStr compares two Debian upstream/revision string segments using deb ordering.
func debCmpStr(a, b string) int {
	ai, bi := 0, 0
	for ai < len(a) || bi < len(b) {
		// Non-digit runs: compare character-by-character with deb char ordering.
		ra, ai2 := debReadAlpha(a, ai)
		rb, bi2 := debReadAlpha(b, bi)
		maxLen := len(ra)
		if len(rb) > maxLen {
			maxLen = len(rb)
		}
		for k := 0; k < maxLen; k++ {
			var ca, cb byte
			if k < len(ra) {
				ca = ra[k]
			}
			if k < len(rb) {
				cb = rb[k]
			}
			if oa, ob := debCharOrd(ca), debCharOrd(cb); oa != ob {
				if oa < ob {
					return -1
				}
				return 1
			}
		}
		ai, bi = ai2, bi2
		// Digit runs: compare numerically.
		an, ai3 := debReadDigit(a, ai)
		bn, bi3 := debReadDigit(b, bi)
		ai, bi = ai3, bi3
		if an != bn {
			if an < bn {
				return -1
			}
			return 1
		}
	}
	return 0
}

// debVersionCompare compares two Debian-format version strings.
// Handles epochs ("1:2.0" > "2.0"), tildes ("1.0~rc1" < "1.0"), and
// mixed alpha/numeric segments per Debian policy manual §5.6.12.
// Returns -1, 0, or +1.
func debVersionCompare(a, b string) int {
	parseDebVer := func(v string) (epoch int, ver, rev string) {
		if ci := strings.Index(v, ":"); ci != -1 {
			epoch, _ = strconv.Atoi(v[:ci])
			v = v[ci+1:]
		}
		ver = v
		if di := strings.LastIndex(v, "-"); di != -1 {
			rev = v[di+1:]
			ver = v[:di]
		}
		return
	}
	ea, va, ra := parseDebVer(a)
	eb, vb, rb := parseDebVer(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := debCmpStr(va, vb); c != 0 {
		return c
	}
	return debCmpStr(ra, rb)
}

// distroPurlTypes are the purl types whose versions follow Debian-style
// "upstream-revision" semantics, where the segment after the last "-" is a
// packaging revision that sorts ABOVE an absent one.
var distroPurlTypes = map[string]bool{
	purlTypeDeb: true,
	purlTypeRPM: true,
	purlTypeAPK: true,
}

// compareVersions orders two version strings for the ecosystem identified by
// purl, returning -1, 0, or +1.
//
// Debian and semver order a trailing "-suffix" in OPPOSITE directions: for deb,
// "1.2.3-2" is a later packaging revision than "1.2.3"; for semver, "1.0.0-rc.2"
// is a prerelease of, and therefore precedes, "1.0.0". One comparator cannot
// serve both, so dispatch on the purl type: distro packages keep the Debian
// comparator, and everything else uses semver precedence when both versions
// parse. Anything that fits neither falls back to the Debian comparator, which
// degrades to a sensible segment-wise comparison for arbitrary strings.
func compareVersions(purl, a, b string) int {
	if distroPurlTypes[purlType(purl)] {
		return debVersionCompare(a, b)
	}
	if isSemver(a) && isSemver(b) {
		return compareSemver(a, b)
	}
	return debVersionCompare(a, b)
}

// addDirectionCount increments the appropriate field of counts based on direction.
func addDirectionCount(counts *ChangeCounts, dir string) {
	switch dir {
	case dirAdded:
		counts.Added++
	case dirRemoved:
		counts.Removed++
	case dirUpgraded:
		counts.Upgraded++
	case dirDowngraded:
		counts.Downgraded++
	default:
		counts.Modified++
	}
}

// addSummaryCount increments the appropriate field of summary based on direction.
func addSummaryCount(s *ChangeSummary, dir string) {
	switch dir {
	case dirAdded:
		s.Added++
	case dirRemoved:
		s.Removed++
	case dirUpgraded:
		s.Upgraded++
	case dirDowngraded:
		s.Downgraded++
	default:
		s.Modified++
	}
}

// classifyDirection returns the direction of a ComponentDiff using
// ecosystem-aware version comparison. Returns one of the dir* constants.
func classifyDirection(d ComponentDiff) string {
	if d.Type != dirModified {
		return d.Type
	}
	if d.PreviousVersion == nil || d.Version == nil {
		return dirModified
	}
	var purl string
	if d.Purl != nil {
		purl = *d.Purl
	}
	cmp := compareVersions(purl, *d.Version, *d.PreviousVersion)
	switch {
	case cmp > 0:
		return dirUpgraded
	case cmp < 0:
		return dirDowngraded
	default:
		return dirModified
	}
}

func versionsEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
