// Package version exposes build-time metadata, injected via -ldflags where the
// build controls the link step and recovered from the Go module's own build
// information where it does not.
package version

import (
	"fmt"
	"runtime/debug"
)

// Sentinels the linker overwrites. A value still equal to its sentinel means no
// -ldflags were passed, which is what Info treats as "ask the build info".
const (
	devVersion  = "dev"
	unknownInfo = "unknown"
)

var (
	Version = devVersion
	Commit  = unknownInfo
	Date    = unknownInfo
)

// readBuildInfo is a variable so tests can supply a debug.BuildInfo rather than
// depend on how the test binary itself was built.
var readBuildInfo = debug.ReadBuildInfo

// Info returns the version, commit and build date, preferring the -ldflags
// values and falling back to the module build information the toolchain embeds.
//
// The fallback is what makes `go install github.com/pfenerty/ocidex/cmd/...`
// report a real version: that path passes no -ldflags, but it does record the
// module version and, for a build from a checkout, the VCS revision and time.
func Info() (version, commit, date string) {
	version, commit, date = Version, Commit, Date

	bi, ok := readBuildInfo()
	if !ok {
		return version, commit, date
	}

	// "(devel)" is what the toolchain records for a build from a working tree
	// rather than a module version, which says no more than the sentinel does.
	if version == devVersion && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}

	for _, s := range bi.Settings {
		if s.Value == "" {
			continue
		}
		switch s.Key {
		case "vcs.revision":
			if commit == unknownInfo {
				commit = s.Value
			}
		case "vcs.time":
			if date == unknownInfo {
				date = s.Value
			}
		}
	}

	return version, commit, date
}

// String renders Info in the one form every OCIDex binary reports it.
func String() string {
	version, commit, date := Info()
	return fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
}
