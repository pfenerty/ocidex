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
			is.Equal(resolveSubjectVersion(tt.bom), tt.want)
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
