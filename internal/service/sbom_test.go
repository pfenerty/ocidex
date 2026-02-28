package service

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

func TestParseSemver(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		wantMajor int
		wantMinor int
		wantPatch int
	}{
		{"full", "1.2.3", 1, 2, 3},
		{"leading v", "v1.2.3", 1, 2, 3},
		{"pre-release", "1.2.3-beta", 1, 2, 3},
		{"build metadata", "1.2.3+build.42", 1, 2, 3},
		{"major minor only", "1.2", 1, 2, -1},
		{"major only", "1", 1, -1, -1},
		{"empty", "", -1, -1, -1},
		{"not a version", "abc", -1, -1, -1},
		{"zeros", "0.0.0", 0, 0, 0},
		{"large numbers", "100.200.300", 100, 200, 300},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			major, minor, patch := parseSemver(tt.version)
			is.Equal(major, tt.wantMajor)
			is.Equal(minor, tt.wantMinor)
			is.Equal(patch, tt.wantPatch)
		})
	}
}

func TestTextOrNull(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  pgtype.Text
	}{
		{"non-empty", "hello", pgtype.Text{String: "hello", Valid: true}},
		{"empty", "", pgtype.Text{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(textOrNull(tt.input), tt.want)
		})
	}
}

func TestResolveSubjectVersion(t *testing.T) {
	props := func(kvs ...string) *[]cdx.Property {
		ps := make([]cdx.Property, 0, len(kvs)/2)
		for i := 0; i < len(kvs); i += 2 {
			ps = append(ps, cdx.Property{Name: kvs[i], Value: kvs[i+1]})
		}
		return &ps
	}

	tests := []struct {
		name string
		bom  *cdx.BOM
		want pgtype.Text
	}{
		{
			name: "normal version used as-is",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
				Version: "20.04",
			}}},
			want: pgtype.Text{String: "20.04", Valid: true},
		},
		{
			name: "digest version falls back to syft OCI label",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Version: "sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214",
				},
				Properties: props(
					"syft:image:labels:org.opencontainers.image.version", "20.04",
				),
			}},
			want: pgtype.Text{String: "20.04", Valid: true},
		},
		{
			name: "empty version falls back to trivy OCI label",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Version:    "",
					Properties: props("aquasecurity:trivy:Labels:org.opencontainers.image.version", "22.04"),
				},
			}},
			want: pgtype.Text{String: "22.04", Valid: true},
		},
		{
			name: "component properties checked before metadata properties",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Version:    "sha256:abc123",
					Properties: props("syft:image:labels:org.opencontainers.image.version", "from-component"),
				},
				Properties: props("syft:image:labels:org.opencontainers.image.version", "from-metadata"),
			}},
			want: pgtype.Text{String: "from-component", Valid: true},
		},
		{
			name: "no version and no properties returns null",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{
				Component: &cdx.Component{Version: ""},
			}},
			want: pgtype.Text{},
		},
		{
			name: "digest version with no properties returns null",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Version: "sha256:abc123",
				},
			}},
			want: pgtype.Text{},
		},
		{
			name: "nil properties handled safely",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Version:    "sha256:abc",
					Properties: nil,
				},
				Properties: nil,
			}},
			want: pgtype.Text{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(resolveSubjectVersion(tt.bom, IngestParams{}), tt.want)
		})
	}

	// Tests with params.Version set (patch-refinement logic).
	paramsTests := []struct {
		name          string
		paramsVersion string
		mcVersion     string
		want          string
	}{
		{
			name:          "mc patch refinement preferred over floating tag",
			paramsVersion: "v1.41",
			mcVersion:     "1.41.5",
			want:          "1.41.5",
		},
		{
			name:          "mc patch 0 is still more specific",
			paramsVersion: "v1.41",
			mcVersion:     "1.41.0",
			want:          "1.41.0",
		},
		{
			name:          "params already full semver, params wins",
			paramsVersion: "v1.41.5",
			mcVersion:     "1.41.5",
			want:          "v1.41.5",
		},
		{
			name:          "different major, params wins",
			paramsVersion: "v2.0",
			mcVersion:     "1.41.5",
			want:          "v2.0",
		},
		{
			name:          "no mc version, params wins",
			paramsVersion: "v1.41",
			mcVersion:     "",
			want:          "v1.41",
		},
		{
			name:          "non-semver params passes through",
			paramsVersion: "nightly",
			mcVersion:     "1.41.5",
			want:          "nightly",
		},
	}

	for _, tt := range paramsTests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
				Version: tt.mcVersion,
			}}}
			got := resolveSubjectVersion(bom, IngestParams{Version: tt.paramsVersion})
			is.Equal(got, pgtype.Text{String: tt.want, Valid: true})
		})
	}
}

func TestResolveArchitecture(t *testing.T) {
	prop := func(name, value string) cdx.Property { return cdx.Property{Name: name, Value: value} }
	props := func(ps ...cdx.Property) *[]cdx.Property { return &ps }

	tests := []struct {
		name   string
		bom    *cdx.BOM
		params IngestParams
		want   string
	}{
		{
			name:   "params wins",
			bom:    &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{}}},
			params: IngestParams{Architecture: "arm64"},
			want:   "arm64",
		},
		{
			name: "label property resolves",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
				Properties: props(prop("syft:image:labels:org.opencontainers.image.architecture", "amd64")),
			}}},
			want: "amd64",
		},
		{
			name: "absent property returns empty",
			bom:  &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{}}},
			want: "",
		},
		{
			name: "syft:image:config.Architecture does not match",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
				Properties: props(prop("syft:image:config.Architecture", "amd64")),
			}}},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(resolveArchitecture(tt.bom, tt.params), tt.want)
		})
	}
}

func TestIntOrNull(t *testing.T) {
	tests := []struct {
		name  string
		input int
		want  pgtype.Int4
	}{
		{"positive", 5, pgtype.Int4{Int32: 5, Valid: true}},
		{"zero", 0, pgtype.Int4{Int32: 0, Valid: true}},
		{"negative", -1, pgtype.Int4{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(intOrNull(tt.input), tt.want)
		})
	}
}
