package service

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
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
