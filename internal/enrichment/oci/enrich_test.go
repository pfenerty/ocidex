package oci

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/enrichment"
)

// registryImage describes a single OCI image to serve from the mock registry.
type registryImage struct {
	architecture        string
	os                  string
	created             string // RFC3339 timestamp or empty
	configLabels        map[string]string
	manifestAnnotations map[string]string
}

// registryIndex describes an OCI image index served at a tag.
type registryIndex struct {
	annotations map[string]string
	imageDigest string // digest of the child image manifest
	imageArch   string
	imageOS     string
}

// buildConfigBlob creates a JSON config blob matching go-containerregistry's expected format.
func buildConfigBlob(img registryImage) []byte {
	config := map[string]any{
		"architecture": img.architecture,
		"os":           img.os,
		"config":       map[string]any{},
	}
	if img.created != "" {
		config["created"] = img.created
	}
	if len(img.configLabels) > 0 {
		config["config"] = map[string]any{
			"Labels": img.configLabels,
		}
	}
	b, _ := json.Marshal(config)
	return b
}

// sha256Digest computes sha256:hex for the given bytes.
func sha256Digest(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h)
}

// buildManifest creates an OCI image manifest JSON with the given config digest and annotations.
func buildManifest(configDigest string, configSize int, annotations map[string]string) []byte {
	m := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    configDigest,
			"size":      configSize,
		},
		"layers": []any{},
	}
	if len(annotations) > 0 {
		m["annotations"] = annotations
	}
	b, _ := json.Marshal(m)
	return b
}

// buildIndexManifest creates an OCI image index manifest JSON.
func buildIndexManifest(imageDigest string, manifestSize int, arch, os string, annotations map[string]string) []byte {
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []any{
			map[string]any{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"digest":    imageDigest,
				"size":      manifestSize,
				"platform": map[string]string{
					"architecture": arch,
					"os":           os,
				},
			},
		},
	}
	if len(annotations) > 0 {
		idx["annotations"] = annotations
	}
	b, _ := json.Marshal(idx)
	return b
}

// registryServer creates an httptest server that serves an OCI image and optionally an index at a tag.
// Returns the server, the manifest digest, and a cleanup function.
func registryServer(t *testing.T, img registryImage, index *registryIndex) (*httptest.Server, string) {
	t.Helper()

	configBlob := buildConfigBlob(img)
	configDigest := sha256Digest(configBlob)

	manifestBytes := buildManifest(configDigest, len(configBlob), img.manifestAnnotations)
	manifestDigest := sha256Digest(manifestBytes)

	var indexBytes []byte
	var indexDigest string
	if index != nil {
		index.imageDigest = manifestDigest
		indexBytes = buildIndexManifest(manifestDigest, len(manifestBytes), index.imageArch, index.imageOS, index.annotations)
		indexDigest = sha256Digest(indexBytes)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Registry ping — required by go-containerregistry.
		if path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Manifests endpoint.
		if strings.Contains(path, "/manifests/") {
			ref := path[strings.LastIndex(path, "/")+1:]

			// Tag-based request — serve index if available, otherwise the manifest.
			if !strings.HasPrefix(ref, "sha256:") {
				if index != nil {
					w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
					w.Header().Set("Docker-Content-Digest", indexDigest)
					_, _ = w.Write(indexBytes)
					return
				}
				// Tag points to single manifest.
				w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
				w.Header().Set("Docker-Content-Digest", manifestDigest)
				_, _ = w.Write(manifestBytes)
				return
			}

			// Digest-based request.
			switch ref {
			case manifestDigest:
				w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
				w.Header().Set("Docker-Content-Digest", manifestDigest)
				_, _ = w.Write(manifestBytes)
			case indexDigest:
				if index != nil {
					w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
					w.Header().Set("Docker-Content-Digest", indexDigest)
					_, _ = w.Write(indexBytes)
				} else {
					http.NotFound(w, r)
				}
			default:
				http.NotFound(w, r)
			}
			return
		}

		// Blob endpoint.
		if strings.Contains(path, "/blobs/") {
			ref := path[strings.LastIndex(path, "/")+1:]
			if ref == configDigest {
				w.Header().Set("Content-Type", "application/vnd.oci.image.config.v1+json")
				w.Header().Set("Docker-Content-Digest", configDigest)
				_, _ = w.Write(configBlob)
				return
			}
			http.NotFound(w, r)
			return
		}

		http.NotFound(w, r)
	}))

	t.Cleanup(srv.Close)
	return srv, manifestDigest
}

// newTestEnricher creates an Enricher configured to talk to the given httptest server.
func newTestEnricher(srv *httptest.Server) *Enricher {
	return NewEnricher(
		WithInsecure(),
		WithRemoteOptions(remote.WithTransport(srv.Client().Transport)),
		WithTimeout(5*time.Second),
	)
}

// enrichAndUnmarshal calls Enrich and unmarshals the result into a Metadata struct.
func enrichAndUnmarshal(t *testing.T, e *Enricher, ref enrichment.SubjectRef) Metadata {
	t.Helper()
	data, err := e.Enrich(t.Context(), ref)
	if err != nil {
		t.Fatalf("Enrich() error: %v", err)
	}
	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("Unmarshal metadata: %v", err)
	}
	return meta
}

// makeRef builds a SubjectRef pointing at the given server.
func makeRef(srv *httptest.Server, digest string, subjectVersion string) enrichment.SubjectRef {
	// Strip http:// scheme to get host:port for artifact name.
	host := strings.TrimPrefix(srv.URL, "http://")
	return enrichment.SubjectRef{
		SBOMId:         pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
		ArtifactType:   "container",
		ArtifactName:   host + "/repo",
		Digest:         digest,
		SubjectVersion: subjectVersion,
	}
}

func TestEnrich_RealWorldScenarios(t *testing.T) {
	tests := []struct {
		name           string
		image          registryImage
		index          *registryIndex
		subjectVersion string
		check          func(t *testing.T, is *is.I, meta Metadata)
	}{
		{
			name: "modern fully-labeled image with all OCI annotations",
			image: registryImage{
				architecture: "amd64",
				os:           "linux",
				created:      "2024-06-15T10:30:00Z",
				configLabels: map[string]string{
					"org.opencontainers.image.version":     "label-version",
					"org.opencontainers.image.source":      "https://label-source.example.com",
					"org.opencontainers.image.revision":    "label-rev",
					"org.opencontainers.image.description": "label description",
					"org.opencontainers.image.vendor":      "label-vendor",
					"org.opencontainers.image.title":       "label-title",
					"custom.label":                         "custom-value",
				},
				manifestAnnotations: map[string]string{
					"org.opencontainers.image.version":       "3.18.4",
					"org.opencontainers.image.source":        "https://github.com/example/repo",
					"org.opencontainers.image.revision":      "a1b2c3d4e5f6",
					"org.opencontainers.image.authors":       "Alpine Linux",
					"org.opencontainers.image.description":   "A minimal Docker image",
					"org.opencontainers.image.base.name":     "scratch",
					"org.opencontainers.image.url":           "https://alpinelinux.org",
					"org.opencontainers.image.documentation": "https://docs.alpinelinux.org",
					"org.opencontainers.image.vendor":        "Alpine",
					"org.opencontainers.image.licenses":      "MIT",
					"org.opencontainers.image.title":         "alpine",
					"org.opencontainers.image.base.digest":   "sha256:basedigest",
					"org.opencontainers.image.ref.name":      "3.18.4",
				},
			},
			check: func(t *testing.T, is *is.I, meta Metadata) {
				is.Equal(meta.Architecture, "amd64")
				is.Equal(meta.OS, "linux")
				is.True(meta.Created != nil)
				// Manifest annotations win over labels.
				is.Equal(meta.ImageVersion, "3.18.4")
				is.Equal(meta.SourceURL, "https://github.com/example/repo")
				is.Equal(meta.Revision, "a1b2c3d4e5f6")
				is.Equal(meta.Authors, "Alpine Linux")
				is.Equal(meta.Description, "A minimal Docker image")
				is.Equal(meta.BaseName, "scratch")
				is.Equal(meta.URL, "https://alpinelinux.org")
				is.Equal(meta.Documentation, "https://docs.alpinelinux.org")
				is.Equal(meta.Vendor, "Alpine")
				is.Equal(meta.Licenses, "MIT")
				is.Equal(meta.Title, "alpine")
				is.Equal(meta.BaseDigest, "sha256:basedigest")
				is.Equal(meta.RefName, "3.18.4")
				// Custom label preserved.
				is.Equal(meta.Labels["custom.label"], "custom-value")
				// Manifest annotations stored raw.
				is.Equal(meta.ManifestAnnotations["org.opencontainers.image.version"], "3.18.4")
			},
		},
		{
			name: "legacy label-schema only image",
			image: registryImage{
				architecture: "arm64",
				os:           "linux",
				configLabels: map[string]string{
					"org.label-schema.version":     "1.2.3",
					"org.label-schema.vcs-url":     "https://github.com/legacy/repo",
					"org.label-schema.vcs-ref":     "deadbeef",
					"org.label-schema.description": "Legacy labeled image",
					"org.label-schema.build-date":  "2023-11-15T08:00:00Z",
					"org.label-schema.url":         "https://legacy.example.com",
					"org.label-schema.usage":       "https://docs.legacy.example.com",
					"org.label-schema.vendor":      "Legacy Corp",
					"org.label-schema.name":        "legacy-image",
				},
			},
			check: func(t *testing.T, is *is.I, meta Metadata) {
				is.Equal(meta.Architecture, "arm64")
				is.Equal(meta.OS, "linux")
				is.Equal(meta.ImageVersion, "1.2.3")
				is.Equal(meta.SourceURL, "https://github.com/legacy/repo")
				is.Equal(meta.Revision, "deadbeef")
				is.Equal(meta.Description, "Legacy labeled image")
				is.Equal(meta.URL, "https://legacy.example.com")
				is.Equal(meta.Documentation, "https://docs.legacy.example.com")
				is.Equal(meta.Vendor, "Legacy Corp")
				is.Equal(meta.Title, "legacy-image")
				// No config.Created, so build-date label is used.
				// Note: extractMetadata checks cfg.Created first;
				// since our mock sets created="" the config blob has no "created" key,
				// so the fallback to label-schema.build-date kicks in.
				is.True(meta.Created != nil)
				want, _ := time.Parse(time.RFC3339, "2023-11-15T08:00:00Z")
				is.True(meta.Created.Equal(want))
			},
		},
		{
			name: "bare keys only image",
			image: registryImage{
				architecture: "amd64",
				os:           "linux",
				configLabels: map[string]string{
					"version":     "10.1",
					"vcs-ref":     "abc123",
					"vcs-url":     "https://github.com/bare/repo",
					"description": "Bare key image",
					"url":         "https://bare.example.com",
					"usage":       "https://docs.bare.example.com",
					"vendor":      "Bare Corp",
					"name":        "bare-image",
					"build-date":  "2024-03-01T12:00:00Z",
				},
			},
			check: func(t *testing.T, is *is.I, meta Metadata) {
				is.Equal(meta.ImageVersion, "10.1")
				is.Equal(meta.Revision, "abc123")
				is.Equal(meta.SourceURL, "https://github.com/bare/repo")
				is.Equal(meta.Description, "Bare key image")
				is.Equal(meta.URL, "https://bare.example.com")
				is.Equal(meta.Documentation, "https://docs.bare.example.com")
				is.Equal(meta.Vendor, "Bare Corp")
				is.Equal(meta.Title, "bare-image")
				is.True(meta.Created != nil)
				want, _ := time.Parse(time.RFC3339, "2024-03-01T12:00:00Z")
				is.True(meta.Created.Equal(want))
			},
		},
		{
			name: "mixed priority - manifest annotations win over labels",
			image: registryImage{
				architecture: "amd64",
				os:           "linux",
				configLabels: map[string]string{
					"org.opencontainers.image.version":     "from-label",
					"org.opencontainers.image.source":      "https://label.example.com",
					"org.opencontainers.image.revision":    "label-rev",
					"org.opencontainers.image.description": "Label description",
					"org.opencontainers.image.vendor":      "Label Vendor",
					"org.opencontainers.image.title":       "label-title",
				},
				manifestAnnotations: map[string]string{
					"org.opencontainers.image.version":     "from-manifest",
					"org.opencontainers.image.source":      "https://manifest.example.com",
					"org.opencontainers.image.revision":    "manifest-rev",
					"org.opencontainers.image.description": "Manifest description",
					"org.opencontainers.image.vendor":      "Manifest Vendor",
					"org.opencontainers.image.title":       "manifest-title",
				},
			},
			check: func(t *testing.T, is *is.I, meta Metadata) {
				// Manifest annotations must win for every field.
				is.Equal(meta.ImageVersion, "from-manifest")
				is.Equal(meta.SourceURL, "https://manifest.example.com")
				is.Equal(meta.Revision, "manifest-rev")
				is.Equal(meta.Description, "Manifest description")
				is.Equal(meta.Vendor, "Manifest Vendor")
				is.Equal(meta.Title, "manifest-title")
			},
		},
		{
			name: "minimal image - no labels or annotations",
			image: registryImage{
				architecture: "riscv64",
				os:           "linux",
			},
			check: func(t *testing.T, is *is.I, meta Metadata) {
				is.Equal(meta.Architecture, "riscv64")
				is.Equal(meta.OS, "linux")
				is.True(meta.Created == nil)
				is.Equal(meta.ImageVersion, "")
				is.Equal(meta.SourceURL, "")
				is.Equal(meta.Revision, "")
				is.Equal(meta.Authors, "")
				is.Equal(meta.Description, "")
				is.Equal(meta.Vendor, "")
				is.Equal(meta.Title, "")
				is.Equal(meta.Licenses, "")
				is.Equal(meta.RefName, "")
				is.True(meta.Labels == nil)
			},
		},
		{
			name: "version and arch only - sufficient enrichment",
			image: registryImage{
				architecture: "amd64",
				os:           "linux",
				configLabels: map[string]string{
					"org.opencontainers.image.version": "2.0.0",
				},
			},
			check: func(t *testing.T, is *is.I, meta Metadata) {
				is.Equal(meta.Architecture, "amd64")
				is.Equal(meta.ImageVersion, "2.0.0")
				// These are sufficient for enrichment gating.
				is.True(meta.Architecture != "" && meta.ImageVersion != "")
				// Everything else is empty.
				is.Equal(meta.SourceURL, "")
				is.Equal(meta.Revision, "")
			},
		},
		{
			name: "version but no architecture - insufficient enrichment",
			image: registryImage{
				// Empty architecture field.
				os: "linux",
				configLabels: map[string]string{
					"org.opencontainers.image.version": "1.0.0",
				},
			},
			check: func(t *testing.T, is *is.I, meta Metadata) {
				is.Equal(meta.Architecture, "")
				is.Equal(meta.ImageVersion, "1.0.0")
				// Insufficient — architecture missing.
				is.True(meta.Architecture == "")
			},
		},
		{
			name: "with parent index annotations as lowest priority",
			image: registryImage{
				architecture: "amd64",
				os:           "linux",
				configLabels: map[string]string{
					"org.opencontainers.image.version": "5.0.0",
					// No licenses label — should fall back to index.
				},
			},
			index: &registryIndex{
				annotations: map[string]string{
					"org.opencontainers.image.version":  "index-version", // should be overridden by label
					"org.opencontainers.image.licenses": "Apache-2.0",    // only in index
					"org.opencontainers.image.vendor":   "Index Vendor",  // only in index
				},
				imageArch: "amd64",
				imageOS:   "linux",
			},
			subjectVersion: "5.0.0",
			check: func(t *testing.T, is *is.I, meta Metadata) {
				// Label wins over index for version.
				is.Equal(meta.ImageVersion, "5.0.0")
				// Index used for fields not present in labels.
				is.Equal(meta.Licenses, "Apache-2.0")
				is.Equal(meta.Vendor, "Index Vendor")
				// Index annotations should be stored raw.
				is.Equal(meta.IndexAnnotations["org.opencontainers.image.licenses"], "Apache-2.0")
			},
		},
		{
			name: "OCI and label-schema coexist - OCI wins",
			image: registryImage{
				architecture: "amd64",
				os:           "linux",
				configLabels: map[string]string{
					"org.opencontainers.image.version":  "oci-ver",
					"org.label-schema.version":          "ls-ver",
					"org.opencontainers.image.source":   "https://oci.example.com",
					"org.label-schema.vcs-url":          "https://ls.example.com",
					"org.opencontainers.image.revision": "oci-rev",
					"org.label-schema.vcs-ref":          "ls-rev",
				},
			},
			check: func(t *testing.T, is *is.I, meta Metadata) {
				is.Equal(meta.ImageVersion, "oci-ver")
				is.Equal(meta.SourceURL, "https://oci.example.com")
				is.Equal(meta.Revision, "oci-rev")
			},
		},
		{
			name: "RefName extraction from manifest annotation",
			image: registryImage{
				architecture: "amd64",
				os:           "linux",
				manifestAnnotations: map[string]string{
					"org.opencontainers.image.ref.name": "v1.2.3-rc1",
				},
			},
			check: func(t *testing.T, is *is.I, meta Metadata) {
				is.Equal(meta.RefName, "v1.2.3-rc1")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			srv, manifestDigest := registryServer(t, tt.image, tt.index)
			e := newTestEnricher(srv)
			ref := makeRef(srv, manifestDigest, tt.subjectVersion)
			meta := enrichAndUnmarshal(t, e, ref)
			tt.check(t, is, meta)
		})
	}
}

func TestEnrich_IndexDigestRejected(t *testing.T) {
	is := is.New(t)

	img := registryImage{architecture: "amd64", os: "linux"}
	idx := &registryIndex{
		imageArch: "amd64",
		imageOS:   "linux",
	}

	srv, _ := registryServer(t, img, idx)

	// Compute the index digest so we can reference it directly.
	configBlob := buildConfigBlob(img)
	configDigest := sha256Digest(configBlob)
	manifestBytes := buildManifest(configDigest, len(configBlob), nil)
	manifestDigest := sha256Digest(manifestBytes)
	indexBytes := buildIndexManifest(manifestDigest, len(manifestBytes), "amd64", "linux", nil)
	indexDigest := sha256Digest(indexBytes)

	e := newTestEnricher(srv)
	ref := makeRef(srv, indexDigest, "")

	_, err := e.Enrich(t.Context(), ref)
	is.True(err != nil)
	is.True(strings.Contains(err.Error(), "manifest list"))
}

func TestEnrich_RegistryError(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	e := newTestEnricher(srv)
	ref := makeRef(srv, "sha256:0000000000000000000000000000000000000000000000000000000000000000", "")

	_, err := e.Enrich(t.Context(), ref)
	is.True(err != nil)
}

func TestEnrich_ParentIndexBestEffort(t *testing.T) {
	is := is.New(t)

	// Image with a version label so the enricher will try to look up a parent index.
	// But no index is served — the enricher should still succeed.
	img := registryImage{
		architecture: "amd64",
		os:           "linux",
		configLabels: map[string]string{
			"org.opencontainers.image.version": "1.0.0",
		},
	}

	srv, manifestDigest := registryServer(t, img, nil)
	e := newTestEnricher(srv)
	ref := makeRef(srv, manifestDigest, "1.0.0")

	meta := enrichAndUnmarshal(t, e, ref)

	is.Equal(meta.Architecture, "amd64")
	is.Equal(meta.ImageVersion, "1.0.0")
	// No index annotations since tag lookup returns the manifest itself (not an index).
	is.True(meta.IndexAnnotations == nil)
}

func TestEnrich_ParentIndexSlowServer(t *testing.T) {
	is := is.New(t)

	img := registryImage{
		architecture: "amd64",
		os:           "linux",
		configLabels: map[string]string{
			"org.opencontainers.image.version": "1.0.0",
		},
	}

	configBlob := buildConfigBlob(img)
	configDigest := sha256Digest(configBlob)
	manifestBytes := buildManifest(configDigest, len(configBlob), nil)
	manifestDigest := sha256Digest(manifestBytes)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Tag-based request (parent index lookup) — delay to trigger timeout.
		if strings.Contains(path, "/manifests/") {
			ref := path[strings.LastIndex(path, "/")+1:]
			if !strings.HasPrefix(ref, "sha256:") {
				// Sleep longer than the parent index 5s timeout.
				time.Sleep(6 * time.Second)
				http.NotFound(w, r)
				return
			}
			if ref == manifestDigest {
				w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
				w.Header().Set("Docker-Content-Digest", manifestDigest)
				_, _ = w.Write(manifestBytes)
				return
			}
		}

		if strings.Contains(path, "/blobs/") {
			ref := path[strings.LastIndex(path, "/")+1:]
			if ref == configDigest {
				w.Header().Set("Content-Type", "application/vnd.oci.image.config.v1+json")
				w.Header().Set("Docker-Content-Digest", configDigest)
				_, _ = w.Write(configBlob)
				return
			}
		}

		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	// Use a longer enricher timeout so the main Enrich call doesn't time out,
	// but the parent index 5s sub-timeout does.
	e := NewEnricher(
		WithInsecure(),
		WithRemoteOptions(remote.WithTransport(srv.Client().Transport)),
		WithTimeout(15*time.Second),
	)
	ref := makeRef(srv, manifestDigest, "1.0.0")

	meta := enrichAndUnmarshal(t, e, ref)

	// Enrichment succeeds even though parent index timed out.
	is.Equal(meta.Architecture, "amd64")
	is.Equal(meta.ImageVersion, "1.0.0")
	is.True(meta.IndexAnnotations == nil)
}
