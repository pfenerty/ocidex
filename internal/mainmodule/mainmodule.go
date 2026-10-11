// Package mainmodule identifies an SBOM's main module — the package built from
// the image's own source repository — and recovers its version when the
// scanner could not. Syft emits version "UNKNOWN" (or none) for a Go main module
// whose build info says "(devel)"; the image's subject version stands in.
//
// Ingest (internal/service) applies it to what it stores; the vuln-worker's
// matcher (internal/vuln/grypematch) applies it to the document it matches, so
// both see the same versions.
package mainmodule

import (
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ociSourceKeys are the property names Syft and Trivy use for the source
// repository URL. Listed in priority order.
var ociSourceKeys = []string{
	"syft:image:labels:org.opencontainers.image.source",
	"aquasecurity:trivy:Labels:org.opencontainers.image.source",
}

// ExtractPath returns the host+path of the SBOM's source repository,
// stripped of scheme and ".git" suffix — e.g.
// "https://github.com/dexidp/dex.git" → "github.com/dexidp/dex".
//
// Used to identify the SBOM's "main module": the package whose source repo
// matches the image. Syft emits version="UNKNOWN" for the Go main module
// when scanning binaries (because runtime/debug.BuildInfo gave it "(devel)"),
// and we use this path to locate that component and backfill its version.
//
// Returns "" when no recognized source label is present.
func ExtractPath(bom *cdx.BOM) string {
	if bom == nil || bom.Metadata == nil {
		return ""
	}
	mc := bom.Metadata.Component
	for _, props := range [][]cdx.Property{
		propertySliceFromComponent(mc),
		propertySlice(bom.Metadata.Properties),
	} {
		for _, p := range props {
			for _, key := range ociSourceKeys {
				if p.Name != key || p.Value == "" {
					continue
				}
				return normalizeSourceURL(p.Value)
			}
		}
	}
	return ""
}

// purlVersion returns a purl's percent-decoded version segment, or "" when it
// has none. Qualifiers and subpath are cut first, since a qualifier value (an
// SSH-form vcs_url) may itself contain "@".
func purlVersion(purl string) string {
	base, _, _ := strings.Cut(purl, "?")
	base, _, _ = strings.Cut(base, "#")
	at := strings.LastIndex(base, "@")
	if at < 0 {
		return ""
	}
	version := base[at+1:]
	if decoded, err := url.PathUnescape(version); err == nil {
		version = decoded
	}
	return version
}

// unknownVersion is Syft's sentinel for a version it could not determine.
const unknownVersion = "UNKNOWN"

func propertySlice(p *[]cdx.Property) []cdx.Property {
	if p == nil {
		return nil
	}
	return *p
}

func propertySliceFromComponent(mc *cdx.Component) []cdx.Property {
	if mc == nil {
		return nil
	}
	return propertySlice(mc.Properties)
}

// normalizeSourceURL strips scheme, leading credentials, and trailing ".git"
// from a repository URL, leaving the canonical host+path form.
func normalizeSourceURL(raw string) string {
	s := raw
	// Strip scheme (https://, git://, git+ssh://, etc.)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip user@ credentials.
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// Strip trailing .git
	s = strings.TrimSuffix(s, ".git")
	// Strip trailing slash.
	s = strings.TrimSuffix(s, "/")
	return s
}

// EffectiveVersion returns the version to persist for a component,
// applying the main-module backfill rule: when a component matches the
// SBOM's main module by purl path or name AND its version is "UNKNOWN" or
// empty, substitute the resolved subjectVersion. Otherwise the original
// version is returned unchanged.
//
// The match is exact, not a prefix match — submodules of the main module
// (e.g. github.com/dexidp/dex/api/v2 under github.com/dexidp/dex) keep their
// original version, since they may legitimately be UNKNOWN for unrelated
// reasons and substituting the parent module's version would be wrong.
func EffectiveVersion(version, name, purl, mainModule, subjectVersion string) string {
	if !IsUnknownVersion(version) {
		return version
	}
	if mainModule == "" || subjectVersion == "" {
		return version
	}
	if !componentMatchesMainModule(name, purl, mainModule) {
		return version
	}
	return subjectVersion
}

// EffectivePurl returns the purl to persist for a component. When the
// purl carries no version of its own but the component has a resolved version
// — the main-module backfill above being the case that matters — the version is
// spliced in, leaving the purl usable as a version-matching key.
//
// This exists because the vulnerability store is keyed entirely by purl and OSV
// matches versions server-side, so a purl with no version matches nothing and is
// skipped outright by vuln.queryablePurls. Without this splice the version that
// EffectiveVersion recovers would reach component.version and stop
// there, leaving the component permanently unscannable.
//
// Diff identity is unaffected: ADR-0019 strips the @version segment before
// comparing components (docs/SBOM_DIFF.md, Rule 1), so a purl that gains a
// version still matches its unversioned self across SBOMs.
func EffectivePurl(purl, version string) string {
	if purl == "" || IsUnknownVersion(version) {
		return purl
	}
	if purlVersion(purl) != "" {
		return purl
	}
	// The spec orders a purl as "pkg:type/namespace/name@version?qualifiers
	// #subpath", so the version is spliced ahead of whichever suffix is present.
	base, suffix := purl, ""
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		base, suffix = purl[:i], purl[i:]
	}
	return base + "@" + encodePurlVersion(version) + suffix
}

// encodePurlVersion percent-encodes a version for use as a purl's version
// segment. url.PathEscape covers "/", "?", "#" and whitespace but leaves "+"
// and "@" alone, both of which would be misread on the way back out, so they
// are encoded explicitly — matching how Syft itself emits "1.2.3%2Bbuild.1".
func encodePurlVersion(v string) string {
	e := url.PathEscape(v)
	e = strings.ReplaceAll(e, "+", "%2B")
	return strings.ReplaceAll(e, "@", "%40")
}

// IsUnknownVersion is true for the literal Syft sentinel "UNKNOWN" and for
// the empty string. Either signals that we don't know the version.
func IsUnknownVersion(v string) bool {
	return v == "" || v == unknownVersion
}

// componentMatchesMainModule returns true when the component's purl path or
// name equals the main-module path. Purl wins when present.
func componentMatchesMainModule(name, purl, mainModule string) bool {
	if purl != "" {
		path := purlPath(purl)
		if path != "" {
			return path == mainModule
		}
	}
	return name == mainModule
}

// purlPath returns the namespace+name portion of a purl, dropping the
// "pkg:<type>/" prefix and any "@version?qualifiers" suffix.
// e.g. "pkg:golang/github.com/dexidp/dex@v1.0?foo=bar" → "github.com/dexidp/dex"
func purlPath(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := purl[len("pkg:"):]
	// Drop type prefix.
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[i+1:]
	} else {
		return ""
	}
	// Drop version + qualifiers.
	if i := strings.IndexAny(rest, "@?"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// Apply rewrites, in place, every component of bom that is the SBOM's main
// module and has no known version: its version becomes subjectVersion and the
// version is spliced into its purl — the same rule ingest applies to what it
// stores (EffectiveVersion, EffectivePurl). It reports how many components it
// changed. Nested components are walked too.
func Apply(bom *cdx.BOM, subjectVersion string) int {
	if bom == nil || bom.Components == nil || subjectVersion == "" {
		return 0
	}
	main := ExtractPath(bom)
	if main == "" {
		return 0
	}
	var changed int
	var walk func(comps []cdx.Component)
	walk = func(comps []cdx.Component) {
		for i := range comps {
			c := &comps[i]
			if v := EffectiveVersion(c.Version, c.Name, c.PackageURL, main, subjectVersion); v != c.Version {
				c.Version = v
				c.PackageURL = EffectivePurl(c.PackageURL, v)
				changed++
			}
			if c.Components != nil {
				walk(*c.Components)
			}
		}
	}
	walk(*bom.Components)
	return changed
}
