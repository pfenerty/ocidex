package service

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

// TestExtractMainModulePath covers the heuristics for identifying the SBOM's
// "main module" — the package whose source repository is the subject of the
// SBOM. Used to backfill UNKNOWN versions on Go main modules where Syft
// emits version='UNKNOWN' because runtime/debug.BuildInfo gave it (devel).
func TestExtractMainModulePath(t *testing.T) {
	tests := []struct {
		name string
		bom  *cdx.BOM
		want string
	}{
		{
			name: "syft image source with .git suffix",
			bom:  bomWithMetadataProperties("syft:image:labels:org.opencontainers.image.source", "https://github.com/dexidp/dex.git"),
			want: "github.com/dexidp/dex",
		},
		{
			name: "syft image source without .git suffix",
			bom:  bomWithMetadataProperties("syft:image:labels:org.opencontainers.image.source", "https://github.com/dexidp/dex"),
			want: "github.com/dexidp/dex",
		},
		{
			name: "trivy aquasecurity-prefixed source label",
			bom:  bomWithMetadataProperties("aquasecurity:trivy:Labels:org.opencontainers.image.source", "https://github.com/example/foo.git"),
			want: "github.com/example/foo",
		},
		{
			name: "no metadata properties",
			bom:  &cdx.BOM{},
			want: "",
		},
		{
			name: "empty source value",
			bom:  bomWithMetadataProperties("syft:image:labels:org.opencontainers.image.source", ""),
			want: "",
		},
		{
			name: "git+ssh scheme",
			bom:  bomWithMetadataProperties("syft:image:labels:org.opencontainers.image.source", "git+ssh://git@github.com/example/foo.git"),
			want: "github.com/example/foo",
		},
		{
			name: "value already path-only",
			bom:  bomWithMetadataProperties("syft:image:labels:org.opencontainers.image.source", "github.com/example/foo"),
			want: "github.com/example/foo",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(extractMainModulePath(tc.bom), tc.want)
		})
	}
}

// TestEffectiveComponentVersion verifies the rule that backfills UNKNOWN/
// empty versions on the SBOM's main module from the resolved subject version.
// All non-main-module components and all components with concrete versions
// are returned unchanged.
func TestEffectiveComponentVersion(t *testing.T) {
	tests := []struct {
		name           string
		componentName  string
		componentPurl  string
		version        string
		mainModule     string
		subjectVersion string
		want           string
	}{
		{
			name:           "main module with UNKNOWN version is backfilled",
			componentName:  "github.com/dexidp/dex",
			componentPurl:  "pkg:golang/github.com/dexidp/dex",
			version:        "UNKNOWN",
			mainModule:     "github.com/dexidp/dex",
			subjectVersion: "v2.31.0",
			want:           "v2.31.0",
		},
		{
			name:           "main module with empty version is backfilled",
			componentName:  "github.com/dexidp/dex",
			componentPurl:  "pkg:golang/github.com/dexidp/dex",
			version:        "",
			mainModule:     "github.com/dexidp/dex",
			subjectVersion: "v2.31.0",
			want:           "v2.31.0",
		},
		{
			name:           "main module match by name when purl is absent",
			componentName:  "github.com/dexidp/dex",
			version:        "UNKNOWN",
			mainModule:     "github.com/dexidp/dex",
			subjectVersion: "v2.31.0",
			want:           "v2.31.0",
		},
		{
			name:           "non-main-module UNKNOWN is left alone",
			componentName:  "github.com/example/other",
			componentPurl:  "pkg:golang/github.com/example/other",
			version:        "UNKNOWN",
			mainModule:     "github.com/dexidp/dex",
			subjectVersion: "v2.31.0",
			want:           "UNKNOWN",
		},
		{
			name:           "main module with concrete version unchanged",
			componentName:  "github.com/dexidp/dex",
			componentPurl:  "pkg:golang/github.com/dexidp/dex",
			version:        "v2.30.0",
			mainModule:     "github.com/dexidp/dex",
			subjectVersion: "v2.31.0",
			want:           "v2.30.0",
		},
		{
			name:           "no main module known — returns version as-is",
			componentName:  "github.com/dexidp/dex",
			version:        "UNKNOWN",
			mainModule:     "",
			subjectVersion: "v2.31.0",
			want:           "UNKNOWN",
		},
		{
			name:           "no subject version — returns version as-is",
			componentName:  "github.com/dexidp/dex",
			componentPurl:  "pkg:golang/github.com/dexidp/dex",
			version:        "UNKNOWN",
			mainModule:     "github.com/dexidp/dex",
			subjectVersion: "",
			want:           "UNKNOWN",
		},
		{
			name:           "submodule of main module is NOT backfilled",
			componentName:  "github.com/dexidp/dex/api/v2",
			componentPurl:  "pkg:golang/github.com/dexidp/dex/api/v2",
			version:        "UNKNOWN",
			mainModule:     "github.com/dexidp/dex",
			subjectVersion: "v2.31.0",
			want:           "UNKNOWN",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			got := effectiveComponentVersion(tc.version, tc.componentName, tc.componentPurl, tc.mainModule, tc.subjectVersion)
			is.Equal(got, tc.want)
		})
	}
}

func bomWithMetadataProperties(key, value string) *cdx.BOM {
	props := []cdx.Property{{Name: key, Value: value}}
	return &cdx.BOM{
		Metadata: &cdx.Metadata{
			Properties: &props,
		},
	}
}

// TestEffectiveComponentPurl covers splicing a resolved version into a purl
// that the scanner emitted without one. This is what makes a Go main module
// matchable against OSV, which keys entirely off the purl's version.
func TestEffectiveComponentPurl(t *testing.T) {
	tests := []struct {
		name    string
		purl    string
		version string
		want    string
	}{
		{
			name:    "bare purl gains the resolved version",
			purl:    "pkg:golang/github.com/fluxcd/kustomize-controller",
			version: "v1.9.5",
			want:    "pkg:golang/github.com/fluxcd/kustomize-controller@v1.9.5",
		},
		{
			name:    "version is spliced ahead of qualifiers",
			purl:    "pkg:golang/example.com/foo?vcs_url=https://example.com/foo",
			version: "v1.2.3",
			want:    "pkg:golang/example.com/foo@v1.2.3?vcs_url=https://example.com/foo",
		},
		{
			name:    "version is spliced ahead of a subpath",
			purl:    "pkg:golang/example.com/foo#cmd/bar",
			version: "v1.2.3",
			want:    "pkg:golang/example.com/foo@v1.2.3#cmd/bar",
		},
		{
			name:    "an @ inside a qualifier is not mistaken for a version",
			purl:    "pkg:golang/example.com/foo?vcs_url=git@github.com:o/r.git",
			version: "v1.2.3",
			want:    "pkg:golang/example.com/foo@v1.2.3?vcs_url=git@github.com:o/r.git",
		},
		{
			name:    "existing version is never overwritten",
			purl:    "pkg:golang/example.com/foo@v1.0.0",
			version: "v1.2.3",
			want:    "pkg:golang/example.com/foo@v1.0.0",
		},
		{
			name:    "build metadata is percent-encoded like Syft emits it",
			purl:    "pkg:generic/foo",
			version: "1.2.3+build.1",
			want:    "pkg:generic/foo@1.2.3%2Bbuild.1",
		},
		{
			name:    "UNKNOWN is not a version",
			purl:    "pkg:golang/example.com/foo",
			version: "UNKNOWN",
			want:    "pkg:golang/example.com/foo",
		},
		{
			name:    "empty version leaves the purl alone",
			purl:    "pkg:golang/example.com/foo",
			version: "",
			want:    "pkg:golang/example.com/foo",
		},
		{
			name:    "empty purl stays empty",
			purl:    "",
			version: "v1.2.3",
			want:    "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			got := effectiveComponentPurl(tc.purl, tc.version)
			is.Equal(got, tc.want)
			// Whatever is spliced in must survive the round trip the vuln
			// refresh performs when it reads the version back out.
			if tc.want != tc.purl {
				is.Equal(purlVersionValue(got), tc.version)
			}
		})
	}
}

// TestFlattenComponentsSplicesMainModuleVersionIntoPurl is the end-to-end
// ingest assertion for the reported kustomize-controller case: the main module
// arrives versionless and must be persisted with the image tag in its purl,
// while a submodule and an unrelated component are left untouched.
func TestFlattenComponentsSplicesMainModuleVersionIntoPurl(t *testing.T) {
	is := is.New(t)

	components := []cdx.Component{
		{
			Name:       "github.com/fluxcd/kustomize-controller",
			Version:    "",
			PackageURL: "pkg:golang/github.com/fluxcd/kustomize-controller",
		},
		{
			Name:       "github.com/fluxcd/kustomize-controller/api",
			Version:    "v1.9.0",
			PackageURL: "pkg:golang/github.com/fluxcd/kustomize-controller/api@v1.9.0",
		},
		{
			Name:       "github.com/fluxcd/pkg/tar",
			Version:    "v1.2.0",
			PackageURL: "pkg:golang/github.com/fluxcd/pkg/tar@v1.2.0",
		},
	}

	flat := flattenComponents(components, pgtype.UUID{},
		"github.com/fluxcd/kustomize-controller", "v1.9.5")
	is.Equal(len(flat), 3)

	// Main module: version backfilled from the image tag, and now carried in
	// the purl so the vuln refresh can match it.
	is.Equal(flat[0].version, "v1.9.5")
	is.Equal(flat[0].purl, "pkg:golang/github.com/fluxcd/kustomize-controller@v1.9.5")

	// Submodule and unrelated dependency keep their own versions and purls.
	is.Equal(flat[1].purl, "pkg:golang/github.com/fluxcd/kustomize-controller/api@v1.9.0")
	is.Equal(flat[2].purl, "pkg:golang/github.com/fluxcd/pkg/tar@v1.2.0")
}
