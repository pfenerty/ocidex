// Package version exposes build-time metadata injected via -ldflags.
package version

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)
