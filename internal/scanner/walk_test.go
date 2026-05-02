package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

type fakeSubmitter struct {
	mu        sync.Mutex
	requests  []ScanRequest
	submitErr error // if set, returned by Submit
}

func (f *fakeSubmitter) Submit(_ context.Context, req ScanRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.submitErr != nil {
		return f.submitErr
	}
	f.requests = append(f.requests, req)
	return nil
}

func (f *fakeSubmitter) submitted() []ScanRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ScanRequest, len(f.requests))
	copy(out, f.requests)
	return out
}

// ociRegistryConfig holds per-path responses for the fake OCI registry server.
type ociRegistryConfig struct {
	// catalog is returned for GET /v2/_catalog
	catalog []string
	// tags maps repo → list of tags
	tags map[string][]string
	// manifests maps "repo:ref" → {digest, mediaType, manifestJSON}
	manifests map[string]fakeManifest
	// blobs maps digest → JSON bytes
	blobs map[string][]byte
	// zotResults is returned for POST /v2/_zot/ext/search
	zotResults []DiscoveredManifest
}

type fakeManifest struct {
	digest    string
	mediaType string
	body      []byte
}

// newFakeOCIRegistry builds a test server that serves OCI Distribution Spec
// responses from the provided config.
func newFakeOCIRegistry(t *testing.T, cfg ociRegistryConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// /v2/_catalog
		if path == "/v2/_catalog" {
			_ = json.NewEncoder(w).Encode(map[string]any{"repositories": cfg.catalog})
			return
		}

		// /v2/_zot/ext/search
		if path == "/v2/_zot/ext/search" {
			results := make([]map[string]any, 0, len(cfg.zotResults))
			for _, m := range cfg.zotResults {
				results = append(results, map[string]any{
					"Digest":    m.Digest,
					"MediaType": m.MediaType,
					"Tag":       m.Tag,
				})
			}
			resp := map[string]any{
				"data": map[string]any{
					"ImageList": map[string]any{
						"Results": results,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// /v2/{repo}/tags/list
		if strings.HasSuffix(path, "/tags/list") {
			repo := strings.TrimPrefix(strings.TrimSuffix(path, "/tags/list"), "/v2/")
			tags := cfg.tags[repo]
			_ = json.NewEncoder(w).Encode(map[string]any{"tags": tags})
			return
		}

		// /v2/{repo}/blobs/{digest}
		if idx := strings.Index(path, "/blobs/"); idx != -1 {
			digest := path[idx+len("/blobs/"):]
			body, ok := cfg.blobs[digest]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(body)
			return
		}

		// /v2/{repo}/manifests/{ref}
		if idx := strings.Index(path, "/manifests/"); idx != -1 {
			repo := strings.TrimPrefix(path[:idx], "/v2/")
			ref := path[idx+len("/manifests/"):]
			key := repo + ":" + ref
			m, ok := cfg.manifests[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", m.mediaType)
			w.Header().Set("Docker-Content-Digest", m.digest)
			if r.Method == http.MethodHead {
				w.Header().Set("Content-Length", "0")
				return
			}
			_, _ = w.Write(m.body)
			return
		}

		http.NotFound(w, r)
	}))
}

func singleArchManifest(configDigest string) []byte {
	b, _ := json.Marshal(map[string]any{
		"config": map[string]any{"digest": configDigest},
	})
	return b
}

func ociIndexManifest(platforms []struct{ digest, arch string }) []byte {
	manifests := make([]map[string]any, len(platforms))
	for i, p := range platforms {
		manifests[i] = map[string]any{
			"digest": p.digest,
			"platform": map[string]any{
				"os":           "linux",
				"architecture": p.arch,
			},
		}
	}
	b, _ := json.Marshal(map[string]any{"manifests": manifests})
	return b
}

func configBlob(arch string) []byte {
	b, _ := json.Marshal(map[string]any{
		"architecture": arch,
	})
	return b
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestWalkRegistry_ExplicitRepos(t *testing.T) {
	is := is.New(t)

	cfg := ociRegistryConfig{
		tags: map[string][]string{
			"myrepo": {"latest", "v1.0"},
		},
		manifests: map[string]fakeManifest{
			"myrepo:latest": {
				digest:    "sha256:digest-latest",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-latest"),
			},
			"myrepo:v1.0": {
				digest:    "sha256:digest-v1",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-v1"),
			},
			"myrepo:sha256:digest-latest": {
				digest:    "sha256:digest-latest",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-latest"),
			},
			"myrepo:sha256:digest-v1": {
				digest:    "sha256:digest-v1",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-v1"),
			},
		},
		blobs: map[string][]byte{
			"sha256:config-latest": configBlob("amd64"),
			"sha256:config-v1":     configBlob("amd64"),
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL, Repositories: []string{"myrepo"}}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 2)
	got := sub.submitted()
	is.Equal(len(got), 2)
	digests := map[string]bool{got[0].Digest: true, got[1].Digest: true}
	is.True(digests["sha256:digest-latest"])
	is.True(digests["sha256:digest-v1"])
}

func TestWalkRegistry_CatalogDiscovery(t *testing.T) {
	is := is.New(t)

	cfg := ociRegistryConfig{
		catalog: []string{"repo1"},
		tags: map[string][]string{
			"repo1": {"v1"},
		},
		manifests: map[string]fakeManifest{
			"repo1:v1": {
				digest:    "sha256:digest-repo1",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-repo1"),
			},
			"repo1:sha256:digest-repo1": {
				digest:    "sha256:digest-repo1",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-repo1"),
			},
		},
		blobs: map[string][]byte{
			"sha256:config-repo1": configBlob("arm64"),
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	// No explicit Repositories → uses catalog discovery.
	reg := service.Registry{URL: srv.URL}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 1)
	got := sub.submitted()
	is.Equal(len(got), 1)
	is.Equal(got[0].Repository, "repo1")
	is.Equal(got[0].Digest, "sha256:digest-repo1")
}

// TestWalkRegistry_KnownDigestDedup verifies that digests present in knownDigests
// are not re-submitted via the untagged-discovery path.
func TestWalkRegistry_KnownDigestDedup(t *testing.T) {
	is := is.New(t)

	// No tags; untagged discovery via Zot returns one digest that is already known.
	cfg := ociRegistryConfig{
		tags: map[string][]string{
			"myrepo": {},
		},
		zotResults: []DiscoveredManifest{
			{
				Digest:    "sha256:already-known",
				MediaType: "application/vnd.oci.image.manifest.v1+json",
			},
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{
		URL:             srv.URL,
		Repositories:    []string{"myrepo"},
		Type:            "zot",
		IncludeUntagged: true,
	}
	knownDigests := map[string]bool{"sha256:already-known": true}
	queued, err := WalkRegistry(t.Context(), reg, sub, knownDigests, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 0)
	is.Equal(len(sub.submitted()), 0)
}

func TestWalkRegistry_MultiArchIndex(t *testing.T) {
	is := is.New(t)

	indexBody := ociIndexManifest([]struct{ digest, arch string }{
		{"sha256:amd64-digest", "amd64"},
		{"sha256:arm64-digest", "arm64"},
	})

	cfg := ociRegistryConfig{
		tags: map[string][]string{
			"myrepo": {"latest"},
		},
		manifests: map[string]fakeManifest{
			"myrepo:latest": {
				digest:    "sha256:index-digest",
				mediaType: "application/vnd.oci.image.index.v1+json",
				body:      indexBody,
			},
			"myrepo:sha256:index-digest": {
				digest:    "sha256:index-digest",
				mediaType: "application/vnd.oci.image.index.v1+json",
				body:      indexBody,
			},
			"myrepo:sha256:amd64-digest": {
				digest:    "sha256:amd64-digest",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-amd64"),
			},
			"myrepo:sha256:arm64-digest": {
				digest:    "sha256:arm64-digest",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-arm64"),
			},
		},
		blobs: map[string][]byte{
			"sha256:config-amd64": configBlob("amd64"),
			"sha256:config-arm64": configBlob("arm64"),
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL, Repositories: []string{"myrepo"}}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 2)
	got := sub.submitted()
	is.Equal(len(got), 2)
	archMap := map[string]bool{got[0].Architecture: true, got[1].Architecture: true}
	is.True(archMap["amd64"])
	is.True(archMap["arm64"])
}

func TestWalkRegistry_TagFilter(t *testing.T) {
	is := is.New(t)

	cfg := ociRegistryConfig{
		tags: map[string][]string{
			"myrepo": {"latest", "v1.0"},
		},
		manifests: map[string]fakeManifest{
			"myrepo:v1.0": {
				digest:    "sha256:digest-v1",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-v1"),
			},
			"myrepo:sha256:digest-v1": {
				digest:    "sha256:digest-v1",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-v1"),
			},
		},
		blobs: map[string][]byte{
			"sha256:config-v1": configBlob("amd64"),
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{
		URL:          srv.URL,
		Repositories: []string{"myrepo"},
		TagPatterns:  []string{"v*"},
	}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 1)
	got := sub.submitted()
	is.Equal(len(got), 1)
	is.Equal(got[0].Tag, "v1.0")
}

// TestWalkRegistry_IncludeUntagged_NonImageType verifies that non-image media types
// returned by the discoverer (e.g. attestations) are silently skipped.
// TestWalkRegistry_HeadFailureSilentlySkipped verifies that a 404 on manifest HEAD
// causes the tag to be silently skipped (no error, 0 queued).
func TestWalkRegistry_HeadFailureSilentlySkipped(t *testing.T) {
	is := is.New(t)

	// Tag "broken" exists in tags/list but has no matching manifest entry → 404.
	cfg := ociRegistryConfig{
		tags: map[string][]string{
			"myrepo": {"broken"},
		},
		manifests: map[string]fakeManifest{}, // intentionally empty
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL, Repositories: []string{"myrepo"}}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 0)
}

// TestWalkRegistry_IndexPlatformArchFromMetadata verifies that when an index
// entry has an empty architecture field, the arch is resolved from the config blob.
func TestWalkRegistry_IndexPlatformArchFromMetadata(t *testing.T) {
	is := is.New(t)

	// Index entry with no architecture — arch should come from the config blob.
	indexBody, _ := json.Marshal(map[string]any{
		"manifests": []map[string]any{
			{"digest": "sha256:platform-digest", "platform": map[string]any{"os": "linux", "architecture": ""}},
		},
	})

	cfg := ociRegistryConfig{
		tags: map[string][]string{"myrepo": {"latest"}},
		manifests: map[string]fakeManifest{
			"myrepo:latest": {
				digest:    "sha256:index-digest",
				mediaType: "application/vnd.oci.image.index.v1+json",
				body:      indexBody,
			},
			"myrepo:sha256:index-digest": {
				digest:    "sha256:index-digest",
				mediaType: "application/vnd.oci.image.index.v1+json",
				body:      indexBody,
			},
			"myrepo:sha256:platform-digest": {
				digest:    "sha256:platform-digest",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:cfg"),
			},
		},
		blobs: map[string][]byte{
			"sha256:cfg": configBlob("arm64"), // arch comes from config blob
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL, Repositories: []string{"myrepo"}}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 1)
	is.Equal(sub.submitted()[0].Architecture, "arm64")
}

// TestWalkRegistry_SubmitError verifies that a Submit failure is silently logged
// and the walk continues (queued count reflects only successfully submitted requests).
func TestWalkRegistry_SubmitError(t *testing.T) {
	is := is.New(t)

	cfg := ociRegistryConfig{
		tags: map[string][]string{"myrepo": {"v1"}},
		manifests: map[string]fakeManifest{
			"myrepo:v1": {
				digest:    "sha256:digest-v1",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:cfg"),
			},
			"myrepo:sha256:digest-v1": {
				digest:    "sha256:digest-v1",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:cfg"),
			},
		},
		blobs: map[string][]byte{"sha256:cfg": configBlob("amd64")},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{submitErr: errors.New("queue full")}
	reg := service.Registry{URL: srv.URL, Repositories: []string{"myrepo"}}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 0) // submit failed → not counted
}

// TestWalkRegistry_IndexSubmitError verifies that a Submit failure inside index
// expansion is silently skipped (queued=0, no error).
func TestWalkRegistry_IndexSubmitError(t *testing.T) {
	is := is.New(t)

	indexBody := ociIndexManifest([]struct{ digest, arch string }{
		{"sha256:amd64-digest", "amd64"},
	})
	cfg := ociRegistryConfig{
		tags: map[string][]string{"myrepo": {"latest"}},
		manifests: map[string]fakeManifest{
			"myrepo:latest": {
				digest:    "sha256:index-digest",
				mediaType: "application/vnd.oci.image.index.v1+json",
				body:      indexBody,
			},
			"myrepo:sha256:index-digest": {
				digest:    "sha256:index-digest",
				mediaType: "application/vnd.oci.image.index.v1+json",
				body:      indexBody,
			},
			"myrepo:sha256:amd64-digest": {
				digest:    "sha256:amd64-digest",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:cfg"),
			},
		},
		blobs: map[string][]byte{"sha256:cfg": configBlob("amd64")},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{submitErr: errors.New("queue full")}
	reg := service.Registry{URL: srv.URL, Repositories: []string{"myrepo"}}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 0)
}

// TestWalkRegistry_IncludeUntagged_DiscoverError verifies that a discovery failure
// (e.g. zot search returns 500) is silently skipped — walk completes with 0 queued.
func TestWalkRegistry_IncludeUntagged_DiscoverError(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/_zot/ext/search" {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/tags/list") {
			_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{}})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{
		URL:             srv.URL,
		Repositories:    []string{"myrepo"},
		Type:            "zot",
		IncludeUntagged: true,
	}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 0)
}

// TestWalkRegistry_CatalogError verifies WalkRegistry returns an error when
// the OCI catalog endpoint returns a non-200 status.
func TestWalkRegistry_CatalogError(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL} // no explicit repos → uses catalog
	_, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())
	is.True(err != nil)
}

// TestWalkRegistry_TagListError verifies that a non-200 tags/list response for a
// repo is silently skipped (warn + 0 queued) rather than aborting the whole walk.
func TestWalkRegistry_TagListError(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/_catalog":
			_ = json.NewEncoder(w).Encode(map[string]any{"repositories": []string{"badrepo"}})
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err) // walk continues; repo silently skipped
	is.Equal(queued, 0)
}

// TestWalkRegistry_RepositoryFilter verifies that repos not matching
// RepositoryPatterns are skipped during catalog walks.
func TestWalkRegistry_RepositoryFilter(t *testing.T) {
	is := is.New(t)

	cfg := ociRegistryConfig{
		catalog: []string{"allowed", "blocked"},
		tags: map[string][]string{
			"allowed": {"v1"},
		},
		manifests: map[string]fakeManifest{
			"allowed:v1": {
				digest:    "sha256:digest-allowed",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:cfg"),
			},
			"allowed:sha256:digest-allowed": {
				digest:    "sha256:digest-allowed",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:cfg"),
			},
		},
		blobs: map[string][]byte{
			"sha256:cfg": configBlob("amd64"),
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{
		URL:                srv.URL,
		RepositoryPatterns: []string{"allowed"},
	}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 1)
	is.Equal(sub.submitted()[0].Repository, "allowed")
}

// TestWalkRegistry_IndexSkipsAttestations verifies that manifest index entries
// with os="unknown" (attestations) are not submitted as scan requests.
func TestWalkRegistry_IndexSkipsAttestations(t *testing.T) {
	is := is.New(t)

	indexBody, _ := json.Marshal(map[string]any{
		"manifests": []map[string]any{
			{"digest": "sha256:real-amd64", "platform": map[string]any{"os": "linux", "architecture": "amd64"}},
			{"digest": "sha256:attestation", "platform": map[string]any{"os": "unknown", "architecture": ""}},
		},
	})

	cfg := ociRegistryConfig{
		tags: map[string][]string{"myrepo": {"latest"}},
		manifests: map[string]fakeManifest{
			"myrepo:latest": {
				digest:    "sha256:index-digest",
				mediaType: "application/vnd.oci.image.index.v1+json",
				body:      indexBody,
			},
			"myrepo:sha256:index-digest": {
				digest:    "sha256:index-digest",
				mediaType: "application/vnd.oci.image.index.v1+json",
				body:      indexBody,
			},
			"myrepo:sha256:real-amd64": {
				digest:    "sha256:real-amd64",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:cfg-amd64"),
			},
		},
		blobs: map[string][]byte{
			"sha256:cfg-amd64": configBlob("amd64"),
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL, Repositories: []string{"myrepo"}}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 1) // only the real linux/amd64 manifest
	is.Equal(sub.submitted()[0].Digest, "sha256:real-amd64")
}

func TestWalkRegistry_IncludeUntagged_NonImageType(t *testing.T) {
	is := is.New(t)

	cfg := ociRegistryConfig{
		tags: map[string][]string{"myrepo": {}},
		zotResults: []DiscoveredManifest{
			{
				Digest:    "sha256:attestation",
				MediaType: "application/vnd.dev.cosign.simplesigning.v1+json",
			},
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{
		URL:             srv.URL,
		Repositories:    []string{"myrepo"},
		Type:            "zot",
		IncludeUntagged: true,
	}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 0)
	is.Equal(len(sub.submitted()), 0)
}

// TestWalkRegistry_IncludeUntagged_IndexExpansion verifies that an OCI index
// returned by the discoverer is expanded into per-platform scan requests.
func TestWalkRegistry_IncludeUntagged_IndexExpansion(t *testing.T) {
	is := is.New(t)

	indexBody := ociIndexManifest([]struct{ digest, arch string }{
		{"sha256:amd64-untagged", "amd64"},
		{"sha256:arm64-untagged", "arm64"},
	})

	cfg := ociRegistryConfig{
		tags: map[string][]string{"myrepo": {}},
		manifests: map[string]fakeManifest{
			"myrepo:sha256:index-untagged": {
				digest:    "sha256:index-untagged",
				mediaType: "application/vnd.oci.image.index.v1+json",
				body:      indexBody,
			},
			"myrepo:sha256:amd64-untagged": {
				digest:    "sha256:amd64-untagged",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:cfg-amd64"),
			},
			"myrepo:sha256:arm64-untagged": {
				digest:    "sha256:arm64-untagged",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:cfg-arm64"),
			},
		},
		blobs: map[string][]byte{
			"sha256:cfg-amd64": configBlob("amd64"),
			"sha256:cfg-arm64": configBlob("arm64"),
		},
		zotResults: []DiscoveredManifest{
			{
				Digest:    "sha256:index-untagged",
				MediaType: "application/vnd.oci.image.index.v1+json",
			},
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{
		URL:             srv.URL,
		Repositories:    []string{"myrepo"},
		Type:            "zot",
		IncludeUntagged: true,
	}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 2)
	got := sub.submitted()
	is.Equal(len(got), 2)
	archs := map[string]bool{got[0].Architecture: true, got[1].Architecture: true}
	is.True(archs["amd64"])
	is.True(archs["arm64"])
}

func TestWalkRegistry_IncludeUntagged_Zot(t *testing.T) {
	is := is.New(t)

	untaggedDigest := "sha256:untagged-only"
	cfg := ociRegistryConfig{
		tags: map[string][]string{
			"myrepo": {}, // no tags
		},
		manifests: map[string]fakeManifest{
			"myrepo:sha256:untagged-only": {
				digest:    untaggedDigest,
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-untagged"),
			},
		},
		blobs: map[string][]byte{
			"sha256:config-untagged": configBlob("amd64"),
		},
		zotResults: []DiscoveredManifest{
			{
				Digest:    untaggedDigest,
				MediaType: "application/vnd.oci.image.manifest.v1+json",
			},
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{
		URL:             srv.URL,
		Repositories:    []string{"myrepo"},
		Type:            "zot",
		IncludeUntagged: true,
	}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 1)
	got := sub.submitted()
	is.Equal(len(got), 1)
	is.Equal(got[0].Digest, untaggedDigest)
}
