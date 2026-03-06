package oci

import (
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pfenerty/ocidex/internal/enrichment"
)

func TestCanEnrich(t *testing.T) {
	e := NewEnricher()

	tests := []struct {
		name   string
		ref    enrichment.SubjectRef
		expect bool
	}{
		{
			name: "container with digest",
			ref: enrichment.SubjectRef{
				ArtifactType: "container",
				Digest:       "sha256:abc123",
			},
			expect: true,
		},
		{
			name: "container without digest",
			ref: enrichment.SubjectRef{
				ArtifactType: "container",
			},
			expect: false,
		},
		{
			name: "library with digest",
			ref: enrichment.SubjectRef{
				ArtifactType: "library",
				Digest:       "sha256:abc123",
			},
			expect: false,
		},
		{
			name:   "empty ref",
			ref:    enrichment.SubjectRef{},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.CanEnrich(tt.ref)
			if got != tt.expect {
				t.Errorf("CanEnrich() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestExtractMetadata(t *testing.T) {
	created := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)

	cfg := &v1.ConfigFile{
		Architecture: "amd64",
		OS:           "linux",
		Created:      v1.Time{Time: created},
		Config: v1.Config{
			Labels: map[string]string{
				"org.opencontainers.image.version":     "3.18.4",
				"org.opencontainers.image.source":      "https://github.com/alpinelinux/docker-alpine",
				"org.opencontainers.image.revision":    "a1b2c3d4",
				"org.opencontainers.image.authors":     "Alpine Linux",
				"org.opencontainers.image.description": "A minimal Docker image based on Alpine Linux",
				"org.opencontainers.image.base.name":   "scratch",
				"custom.label":                         "custom-value",
			},
		},
	}

	meta := extractMetadata(cfg, nil, nil)

	if meta.Architecture != "amd64" {
		t.Errorf("Architecture = %q, want %q", meta.Architecture, "amd64")
	}
	if meta.OS != "linux" {
		t.Errorf("OS = %q, want %q", meta.OS, "linux")
	}
	if meta.Created == nil || !meta.Created.Equal(created) {
		t.Errorf("Created = %v, want %v", meta.Created, created)
	}
	if meta.ImageVersion != "3.18.4" {
		t.Errorf("ImageVersion = %q, want %q", meta.ImageVersion, "3.18.4")
	}
	if meta.SourceURL != "https://github.com/alpinelinux/docker-alpine" {
		t.Errorf("SourceURL = %q, want correct URL", meta.SourceURL)
	}
	if meta.Revision != "a1b2c3d4" {
		t.Errorf("Revision = %q, want %q", meta.Revision, "a1b2c3d4")
	}
	if meta.Authors != "Alpine Linux" {
		t.Errorf("Authors = %q, want %q", meta.Authors, "Alpine Linux")
	}
	if meta.Description != "A minimal Docker image based on Alpine Linux" {
		t.Errorf("Description = %q, want correct value", meta.Description)
	}
	if meta.BaseName != "scratch" {
		t.Errorf("BaseName = %q, want %q", meta.BaseName, "scratch")
	}
	if meta.Labels["custom.label"] != "custom-value" {
		t.Error("expected custom label to be preserved")
	}
}

func TestExtractMetadata_EmptyConfig(t *testing.T) {
	cfg := &v1.ConfigFile{}
	meta := extractMetadata(cfg, nil, nil)

	if meta.Architecture != "" {
		t.Errorf("Architecture = %q, want empty", meta.Architecture)
	}
	if meta.Created != nil {
		t.Errorf("Created = %v, want nil", meta.Created)
	}
	if meta.Labels != nil {
		t.Errorf("Labels = %v, want nil", meta.Labels)
	}
}

func TestExtractField(t *testing.T) {
	tests := []struct {
		name                string
		key                 string
		manifestAnnotations map[string]string
		labels              map[string]string
		indexAnnotations    map[string]string
		want                string
	}{
		{
			name: "manifest wins over labels and index",
			key:  "org.opencontainers.image.version",
			manifestAnnotations: map[string]string{
				"org.opencontainers.image.version": "manifest-ver",
			},
			labels: map[string]string{
				"org.opencontainers.image.version": "label-ver",
			},
			indexAnnotations: map[string]string{
				"org.opencontainers.image.version": "index-ver",
			},
			want: "manifest-ver",
		},
		{
			name: "labels win over index when manifest missing",
			key:  "org.opencontainers.image.version",
			labels: map[string]string{
				"org.opencontainers.image.version": "label-ver",
			},
			indexAnnotations: map[string]string{
				"org.opencontainers.image.version": "index-ver",
			},
			want: "label-ver",
		},
		{
			name: "index used as fallback",
			key:  "org.opencontainers.image.version",
			indexAnnotations: map[string]string{
				"org.opencontainers.image.version": "index-ver",
			},
			want: "index-ver",
		},
		{
			name: "empty string skipped in manifest",
			key:  "org.opencontainers.image.version",
			manifestAnnotations: map[string]string{
				"org.opencontainers.image.version": "",
			},
			labels: map[string]string{
				"org.opencontainers.image.version": "label-ver",
			},
			want: "label-ver",
		},
		{
			name: "all nil maps",
			key:  "org.opencontainers.image.version",
			want: "",
		},
		{
			name:                "key not present in any source",
			key:                 "org.opencontainers.image.missing",
			manifestAnnotations: map[string]string{"other": "val"},
			labels:              map[string]string{"other": "val"},
			indexAnnotations:    map[string]string{"other": "val"},
			want:                "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractField(tt.key, tt.manifestAnnotations, tt.labels, tt.indexAnnotations)
			if got != tt.want {
				t.Errorf("extractField() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractMetadata_AnnotationPriority(t *testing.T) {
	cfg := &v1.ConfigFile{
		Config: v1.Config{
			Labels: map[string]string{
				"org.opencontainers.image.version": "from-labels",
				"org.opencontainers.image.vendor":  "label-vendor",
			},
		},
	}
	manifest := map[string]string{
		"org.opencontainers.image.version": "from-manifest",
		"org.opencontainers.image.url":     "https://manifest.example.com",
	}
	index := map[string]string{
		"org.opencontainers.image.version":  "from-index",
		"org.opencontainers.image.vendor":   "index-vendor",
		"org.opencontainers.image.licenses": "Apache-2.0",
	}

	meta := extractMetadata(cfg, manifest, index)

	// Manifest wins for version.
	if meta.ImageVersion != "from-manifest" {
		t.Errorf("ImageVersion = %q, want %q", meta.ImageVersion, "from-manifest")
	}
	// Labels win for vendor (no manifest entry).
	if meta.Vendor != "label-vendor" {
		t.Errorf("Vendor = %q, want %q", meta.Vendor, "label-vendor")
	}
	// Index used as fallback for licenses.
	if meta.Licenses != "Apache-2.0" {
		t.Errorf("Licenses = %q, want %q", meta.Licenses, "Apache-2.0")
	}
	// Manifest-only field.
	if meta.URL != "https://manifest.example.com" {
		t.Errorf("URL = %q, want %q", meta.URL, "https://manifest.example.com")
	}
	// Raw annotations preserved.
	if meta.ManifestAnnotations["org.opencontainers.image.version"] != "from-manifest" {
		t.Error("expected manifest annotations to be preserved")
	}
	if meta.IndexAnnotations["org.opencontainers.image.licenses"] != "Apache-2.0" {
		t.Error("expected index annotations to be preserved")
	}
}

func TestExtractMetadata_NewConvenienceFields(t *testing.T) {
	cfg := &v1.ConfigFile{
		Config: v1.Config{
			Labels: map[string]string{
				"org.opencontainers.image.url":           "https://example.com",
				"org.opencontainers.image.documentation": "https://docs.example.com",
				"org.opencontainers.image.vendor":        "ACME Corp",
				"org.opencontainers.image.licenses":      "MIT",
				"org.opencontainers.image.title":         "myimage",
				"org.opencontainers.image.base.digest":   "sha256:abc123",
			},
		},
	}

	meta := extractMetadata(cfg, nil, nil)

	if meta.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q", meta.URL, "https://example.com")
	}
	if meta.Documentation != "https://docs.example.com" {
		t.Errorf("Documentation = %q, want %q", meta.Documentation, "https://docs.example.com")
	}
	if meta.Vendor != "ACME Corp" {
		t.Errorf("Vendor = %q, want %q", meta.Vendor, "ACME Corp")
	}
	if meta.Licenses != "MIT" {
		t.Errorf("Licenses = %q, want %q", meta.Licenses, "MIT")
	}
	if meta.Title != "myimage" {
		t.Errorf("Title = %q, want %q", meta.Title, "myimage")
	}
	if meta.BaseDigest != "sha256:abc123" {
		t.Errorf("BaseDigest = %q, want %q", meta.BaseDigest, "sha256:abc123")
	}
}

func TestExtractMetadata_LabelSchemaFallback(t *testing.T) {
	tests := []struct {
		name   string
		cfg    *v1.ConfigFile
		checks func(t *testing.T, meta Metadata)
	}{
		{
			name: "label-schema fields used as fallback",
			cfg: &v1.ConfigFile{
				Config: v1.Config{
					Labels: map[string]string{
						"org.label-schema.version":     "1.2.3",
						"org.label-schema.vcs-url":     "https://github.com/example/repo",
						"org.label-schema.vcs-ref":     "deadbeef",
						"org.label-schema.description": "An example image",
						"org.label-schema.url":         "https://example.com",
						"org.label-schema.usage":       "https://docs.example.com",
						"org.label-schema.vendor":      "Example Corp",
						"org.label-schema.name":        "example-image",
					},
				},
			},
			checks: func(t *testing.T, meta Metadata) {
				if meta.ImageVersion != "1.2.3" {
					t.Errorf("ImageVersion = %q, want %q", meta.ImageVersion, "1.2.3")
				}
				if meta.SourceURL != "https://github.com/example/repo" {
					t.Errorf("SourceURL = %q, want %q", meta.SourceURL, "https://github.com/example/repo")
				}
				if meta.Revision != "deadbeef" {
					t.Errorf("Revision = %q, want %q", meta.Revision, "deadbeef")
				}
				if meta.Description != "An example image" {
					t.Errorf("Description = %q, want %q", meta.Description, "An example image")
				}
				if meta.URL != "https://example.com" {
					t.Errorf("URL = %q, want %q", meta.URL, "https://example.com")
				}
				if meta.Documentation != "https://docs.example.com" {
					t.Errorf("Documentation = %q, want %q", meta.Documentation, "https://docs.example.com")
				}
				if meta.Vendor != "Example Corp" {
					t.Errorf("Vendor = %q, want %q", meta.Vendor, "Example Corp")
				}
				if meta.Title != "example-image" {
					t.Errorf("Title = %q, want %q", meta.Title, "example-image")
				}
			},
		},
		{
			name: "bare keys used as fallback",
			cfg: &v1.ConfigFile{
				Config: v1.Config{
					Labels: map[string]string{
						"version":     "10.1",
						"vcs-ref":     "deadbeef",
						"vcs-url":     "https://github.com/example/repo",
						"description": "A bare-key image",
						"url":         "https://example.com",
						"usage":       "https://docs.example.com",
						"vendor":      "Example Corp",
						"name":        "example-image",
					},
				},
			},
			checks: func(t *testing.T, meta Metadata) {
				if meta.ImageVersion != "10.1" {
					t.Errorf("ImageVersion = %q, want %q", meta.ImageVersion, "10.1")
				}
				if meta.Revision != "deadbeef" {
					t.Errorf("Revision = %q, want %q", meta.Revision, "deadbeef")
				}
				if meta.SourceURL != "https://github.com/example/repo" {
					t.Errorf("SourceURL = %q, want %q", meta.SourceURL, "https://github.com/example/repo")
				}
				if meta.Description != "A bare-key image" {
					t.Errorf("Description = %q, want %q", meta.Description, "A bare-key image")
				}
				if meta.URL != "https://example.com" {
					t.Errorf("URL = %q, want %q", meta.URL, "https://example.com")
				}
				if meta.Documentation != "https://docs.example.com" {
					t.Errorf("Documentation = %q, want %q", meta.Documentation, "https://docs.example.com")
				}
				if meta.Vendor != "Example Corp" {
					t.Errorf("Vendor = %q, want %q", meta.Vendor, "Example Corp")
				}
				if meta.Title != "example-image" {
					t.Errorf("Title = %q, want %q", meta.Title, "example-image")
				}
			},
		},
		{
			name: "OCI annotations win over label-schema",
			cfg: &v1.ConfigFile{
				Config: v1.Config{
					Labels: map[string]string{
						"org.opencontainers.image.version":       "oci-ver",
						"org.label-schema.version":               "ls-ver",
						"org.opencontainers.image.source":        "https://oci.example.com",
						"org.label-schema.vcs-url":               "https://ls.example.com",
						"org.opencontainers.image.revision":      "oci-rev",
						"org.label-schema.vcs-ref":               "ls-rev",
						"org.opencontainers.image.description":   "OCI description",
						"org.label-schema.description":           "LS description",
						"org.opencontainers.image.url":           "https://oci-url.example.com",
						"org.label-schema.url":                   "https://ls-url.example.com",
						"org.opencontainers.image.documentation": "https://oci-docs.example.com",
						"org.label-schema.usage":                 "https://ls-docs.example.com",
						"org.opencontainers.image.vendor":        "OCI Vendor",
						"org.label-schema.vendor":                "LS Vendor",
						"org.opencontainers.image.title":         "oci-title",
						"org.label-schema.name":                  "ls-title",
					},
				},
			},
			checks: func(t *testing.T, meta Metadata) {
				if meta.ImageVersion != "oci-ver" {
					t.Errorf("ImageVersion = %q, want %q", meta.ImageVersion, "oci-ver")
				}
				if meta.SourceURL != "https://oci.example.com" {
					t.Errorf("SourceURL = %q, want %q", meta.SourceURL, "https://oci.example.com")
				}
				if meta.Revision != "oci-rev" {
					t.Errorf("Revision = %q, want %q", meta.Revision, "oci-rev")
				}
				if meta.Description != "OCI description" {
					t.Errorf("Description = %q, want %q", meta.Description, "OCI description")
				}
				if meta.URL != "https://oci-url.example.com" {
					t.Errorf("URL = %q, want %q", meta.URL, "https://oci-url.example.com")
				}
				if meta.Documentation != "https://oci-docs.example.com" {
					t.Errorf("Documentation = %q, want %q", meta.Documentation, "https://oci-docs.example.com")
				}
				if meta.Vendor != "OCI Vendor" {
					t.Errorf("Vendor = %q, want %q", meta.Vendor, "OCI Vendor")
				}
				if meta.Title != "oci-title" {
					t.Errorf("Title = %q, want %q", meta.Title, "oci-title")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := extractMetadata(tt.cfg, nil, nil)
			tt.checks(t, meta)
		})
	}
}

func TestExtractMetadata_LabelSchemaBuildDate(t *testing.T) {
	buildDate := "2023-11-15T08:00:00Z"
	want, _ := time.Parse(time.RFC3339, buildDate)

	tests := []struct {
		name   string
		labels map[string]string
	}{
		{
			name:   "org.label-schema.build-date",
			labels: map[string]string{"org.label-schema.build-date": buildDate},
		},
		{
			name:   "bare build-date",
			labels: map[string]string{"build-date": buildDate},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &v1.ConfigFile{Config: v1.Config{Labels: tt.labels}}
			meta := extractMetadata(cfg, nil, nil)
			if meta.Created == nil {
				t.Fatal("Created = nil, want non-nil")
			}
			if !meta.Created.Equal(want) {
				t.Errorf("Created = %v, want %v", meta.Created, want)
			}
		})
	}
}

func TestExtractMetadata_RefName(t *testing.T) {
	cfg := &v1.ConfigFile{
		Config: v1.Config{
			Labels: map[string]string{
				"org.opencontainers.image.ref.name": "v1.2.3",
			},
		},
	}

	meta := extractMetadata(cfg, nil, nil)

	if meta.RefName != "v1.2.3" {
		t.Errorf("RefName = %q, want %q", meta.RefName, "v1.2.3")
	}
}

func TestExtractMetadata_RefName_ManifestPriority(t *testing.T) {
	cfg := &v1.ConfigFile{
		Config: v1.Config{
			Labels: map[string]string{
				"org.opencontainers.image.ref.name": "from-labels",
			},
		},
	}
	manifest := map[string]string{
		"org.opencontainers.image.ref.name": "from-manifest",
	}

	meta := extractMetadata(cfg, manifest, nil)

	if meta.RefName != "from-manifest" {
		t.Errorf("RefName = %q, want %q", meta.RefName, "from-manifest")
	}
}

func TestName(t *testing.T) {
	e := NewEnricher()
	if e.Name() != "oci-metadata" {
		t.Errorf("Name() = %q, want %q", e.Name(), "oci-metadata")
	}
}

// Ensure Enricher satisfies the enrichment.Enricher interface.
var _ enrichment.Enricher = (*Enricher)(nil)
