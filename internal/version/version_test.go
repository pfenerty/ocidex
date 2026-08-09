package version

import (
	"runtime/debug"
	"testing"

	"github.com/matryer/is"
)

// stubBuildInfo replaces the build-info source for the duration of a test, so
// the assertions do not depend on how the test binary itself was built.
func stubBuildInfo(t *testing.T, mainVersion, revision, vcsTime string) {
	t.Helper()
	prev := readBuildInfo
	t.Cleanup(func() { readBuildInfo = prev })
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{Version: mainVersion},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: revision},
				{Key: "vcs.time", Value: vcsTime},
			},
		}, true
	}
}

// stubVars sets the linker-injected values for the duration of a test.
func stubVars(t *testing.T, version, commit, date string) {
	t.Helper()
	pv, pc, pd := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = pv, pc, pd })
	Version, Commit, Date = version, commit, date
}

func TestInfoPrefersLdflags(t *testing.T) {
	is := is.New(t)
	stubVars(t, "v1.2.3", "deadbeef", "2026-01-01T00:00:00Z")
	stubBuildInfo(t, "v9.9.9", "cafebabe", "2026-08-08T00:00:00Z")

	version, commit, date := Info()
	is.Equal(version, "v1.2.3")
	is.Equal(commit, "deadbeef")
	is.Equal(date, "2026-01-01T00:00:00Z")
}

// TestInfoFallsBackToBuildInfo covers the `go install` path: no -ldflags, but
// the toolchain records the module version and the VCS stamps.
func TestInfoFallsBackToBuildInfo(t *testing.T) {
	is := is.New(t)
	stubVars(t, devVersion, unknownInfo, unknownInfo)
	stubBuildInfo(t, "v0.4.0", "cafebabe", "2026-08-08T00:00:00Z")

	version, commit, date := Info()
	is.Equal(version, "v0.4.0")
	is.Equal(commit, "cafebabe")
	is.Equal(date, "2026-08-08T00:00:00Z")
}

// A working-tree build records "(devel)" as the module version, which says no
// more than the sentinel does — but its VCS stamps are still worth having.
func TestInfoIgnoresDevelVersion(t *testing.T) {
	is := is.New(t)
	stubVars(t, devVersion, unknownInfo, unknownInfo)
	stubBuildInfo(t, "(devel)", "cafebabe", "2026-08-08T00:00:00Z")

	version, commit, date := Info()
	is.Equal(version, devVersion)
	is.Equal(commit, "cafebabe")
	is.Equal(date, "2026-08-08T00:00:00Z")
}

// A binary built outside a module and outside a checkout: no build info at all,
// or empty settings. Every field keeps its sentinel rather than going blank.
func TestInfoWithoutBuildInfo(t *testing.T) {
	is := is.New(t)
	stubVars(t, devVersion, unknownInfo, unknownInfo)
	prev := readBuildInfo
	t.Cleanup(func() { readBuildInfo = prev })
	readBuildInfo = func() (*debug.BuildInfo, bool) { return nil, false }

	version, commit, date := Info()
	is.Equal(version, devVersion)
	is.Equal(commit, unknownInfo)
	is.Equal(date, unknownInfo)
}

func TestString(t *testing.T) {
	is := is.New(t)
	stubVars(t, "v1.2.3", "deadbeef", "2026-01-01T00:00:00Z")
	is.Equal(String(), "v1.2.3 (commit deadbeef, built 2026-01-01T00:00:00Z)")
}
