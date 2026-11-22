package service

import (
	"regexp"
	"strings"
)

// prereleaseSuffix matches the part of a version after its first '-' when that
// part is a prerelease tag: rc, pre, alpha, beta or dev, optionally numbered.
var prereleaseSuffix = regexp.MustCompile(`(?i)^(rc|pre|alpha|beta|dev)(\.?\d+)?$`)

// VersionLine splits a subject version into the line it belongs to. variant is
// the suffix after the first '-' ("trixie" in "3.15.2-trixie"), and prerelease
// reports a suffix that is a prerelease tag instead, which has no variant of
// its own. It is the rule behind sbom.version_variant and
// sbom.version_prerelease and behind variantOf() in the web client; all three
// are tested against web/src/utils/versionLine.golden.json.
func VersionLine(subjectVersion string) (variant string, prerelease bool) {
	_, suffix, ok := strings.Cut(subjectVersion, "-")
	if !ok {
		return "", false
	}
	if prereleaseSuffix.MatchString(suffix) {
		return "", true
	}
	return suffix, false
}
