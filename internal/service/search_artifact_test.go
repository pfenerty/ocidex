package service

import (
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/pfenerty/ocidex/internal/repository"
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
	is.Equal(len(paginateVersions(vs, 2, 5)), 0)                        // offset past end
	is.Equal(keys(paginateVersions(vs, 0, 0)), []string{"a", "b", "c"}) // limit 0 = all
}

func TestSortVersionsBySeverity_WorstFirst(t *testing.T) {
	is := is.New(t)
	// One critical outranks any number of highs: the comparison walks the scale
	// rank by rank rather than totalling.
	vs := []ArtifactVersion{
		{VersionKey: "many-highs", Vulns: &VulnSummary{High: 40, Total: 40}},
		{VersionKey: "one-critical", Vulns: &VulnSummary{Critical: 1, Total: 1}},
		{VersionKey: "one-low", Vulns: &VulnSummary{Low: 1, Total: 1}},
	}
	sortVersionsBySeverity(vs, true)
	is.Equal(keys(vs), []string{"one-critical", "many-highs", "one-low"})
}

func TestSortVersionsBySeverity_UnscannedSortsLastInBothDirections(t *testing.T) {
	is := is.New(t)
	// A nil summary is unknown, not clean. Ascending means least-worst first,
	// and letting "never scanned" take that spot is exactly the ADR-044 claim
	// the column exists to avoid making.
	for _, desc := range []bool{true, false} {
		vs := []ArtifactVersion{
			{VersionKey: "unscanned"},
			{VersionKey: "critical", Vulns: &VulnSummary{Critical: 1, Total: 1}},
			{VersionKey: "low", Vulns: &VulnSummary{Low: 1, Total: 1}},
		}
		sortVersionsBySeverity(vs, desc)
		is.Equal(keys(vs)[2], "unscanned")
	}
}

func TestSortVersionsBySeverity_TiesKeepModeOrder(t *testing.T) {
	is := is.New(t)
	// The severity sort layers on top of the mode's ordering; equal severity
	// must not scramble the semver order underneath it.
	vs := []ArtifactVersion{
		{VersionKey: "2.0.0", Vulns: &VulnSummary{High: 1, Total: 1}},
		{VersionKey: "1.0.0", Vulns: &VulnSummary{High: 1, Total: 1}},
	}
	sortVersionsBySeverity(vs, true)
	is.Equal(keys(vs), []string{"2.0.0", "1.0.0"})
}

func TestParseVersionColumnSort(t *testing.T) {
	is := is.New(t)
	is.Equal(ParseVersionColumnSort("severity", ""), VersionColumnSort{Column: "severity", Desc: true})
	is.Equal(ParseVersionColumnSort("severity", "asc"), VersionColumnSort{Column: "severity", Desc: false})
	// Anything unrecognised falls back to the mode's own ordering rather than
	// erroring, so a hand-edited URL shows the default list.
	is.Equal(ParseVersionColumnSort("bogus", "desc"), VersionColumnSort{})
	is.Equal(ParseVersionColumnSort("", "desc"), VersionColumnSort{})
}

func TestArtifactVersionFromRow_ZeroCountsMeanNoSummary(t *testing.T) {
	is := is.New(t)
	// sbom_vuln_rollup only holds SBOMs with at least one finding, so an
	// all-zero row is a missing row. Mapping it to an all-zero summary would let
	// the UI render "clean" for something that may never have been scanned.
	is.Equal(artifactVersionFromRow(repository.ListArtifactVersionsRow{}).Vulns, (*VulnSummary)(nil))

	withFindings := artifactVersionFromRow(repository.ListArtifactVersionsRow{
		VulnCritical: 1, VulnLow: 2,
	})
	is.Equal(withFindings.Vulns, &VulnSummary{Critical: 1, Low: 2, Total: 3})
}

// sbom_vuln_rollup holds a row only for an SBOM with at least one finding, so
// all-zero counts mean the row was missing: "no known vulnerabilities" *or*
// "never scanned", indistinguishably. A non-nil all-zero summary would let the
// UI render that as a clean zero, which is the ADR-044 bug.
func TestVulnSummaryOrNil(t *testing.T) {
	is := is.New(t)

	is.Equal(vulnSummaryOrNil(0, 0, 0, 0, 0), (*VulnSummary)(nil))

	got := vulnSummaryOrNil(1, 2, 3, 4, 5)
	is.True(got != nil)
	is.Equal(got.Critical, 1)
	is.Equal(got.High, 2)
	is.Equal(got.Medium, 3)
	is.Equal(got.Low, 4)
	is.Equal(got.Unknown, 5)
	is.Equal(got.Total, 15)

	// A finding of unknown severity alone still counts as scanned.
	is.True(vulnSummaryOrNil(0, 0, 0, 0, 1) != nil)
}

// The ORDER BY in ListArtifacts flips its severity keys by multiplying them
// instead of carrying a second set, which works only because counts are
// non-negative. Getting the sign backwards would silently invert the sort.
func TestSortDirSign(t *testing.T) {
	is := is.New(t)
	is.Equal(sortDirSign(true), int32(1))   // desc: worst first
	is.Equal(sortDirSign(false), int32(-1)) // asc
}
