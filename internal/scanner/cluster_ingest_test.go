package scanner

import (
	"encoding/json"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// TestSubmitForRunningImage_SingleArch covers the ordinary case: the cluster
// reported an image manifest digest, and one scan job comes out of it.
func TestSubmitForRunningImage_SingleArch(t *testing.T) {
	is := is.New(t)

	cfg := ociRegistryConfig{
		manifests: map[string]fakeManifest{
			"myrepo:sha256:image-digest": {
				digest:    "sha256:image-digest",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-1"),
			},
		},
		blobs: map[string][]byte{
			"sha256:config-1": []byte(`{"architecture":"amd64"}`),
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL, Enabled: true, ID: "reg-1"}
	queued, err := SubmitForRunningImage(t.Context(), reg, "myrepo", "sha256:image-digest", "v1.2", sub, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 1)
	got := sub.submitted()
	is.Equal(len(got), 1)
	is.Equal(got[0].Repository, "myrepo")
	is.Equal(got[0].Digest, "sha256:image-digest")
	is.Equal(got[0].Tag, "v1.2")
	is.Equal(got[0].RegistryID, "reg-1")
	// Nothing to expand, so no index digest is claimed.
	is.Equal(got[0].IndexDigest, "")
}

// TestSubmitForRunningImage_IndexExpands is the case the cluster path exists
// for: containerd resolves a multi-arch reference to the *index* digest, so the
// digest a workload reports is not a scannable image. Submitting it unexpanded
// would enqueue a manifest list the scanner cannot read.
func TestSubmitForRunningImage_IndexExpands(t *testing.T) {
	is := is.New(t)

	indexBody, _ := json.Marshal(map[string]any{
		"manifests": []map[string]any{
			{"digest": "sha256:amd64", "platform": map[string]any{"os": "linux", "architecture": "amd64"}},
			{"digest": "sha256:arm64", "platform": map[string]any{"os": "linux", "architecture": "arm64"}},
			// An attestation, which carries no platform and is not an image.
			{"digest": "sha256:attest", "platform": map[string]any{"os": "unknown", "architecture": ""}},
		},
	})

	cfg := ociRegistryConfig{
		manifests: map[string]fakeManifest{
			"myrepo:sha256:index-digest": {
				digest:    "sha256:index-digest",
				mediaType: "application/vnd.oci.image.index.v1+json",
				body:      indexBody,
			},
			"myrepo:sha256:amd64": {
				digest:    "sha256:amd64",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-amd64"),
			},
			"myrepo:sha256:arm64": {
				digest:    "sha256:arm64",
				mediaType: "application/vnd.oci.image.manifest.v1+json",
				body:      singleArchManifest("sha256:config-arm64"),
			},
		},
		blobs: map[string][]byte{
			"sha256:config-amd64": []byte(`{"architecture":"amd64"}`),
			"sha256:config-arm64": []byte(`{"architecture":"arm64"}`),
		},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL, Enabled: true}
	queued, err := SubmitForRunningImage(t.Context(), reg, "myrepo", "sha256:index-digest", "v1.2", sub, discardLogger())

	is.NoErr(err)
	is.Equal(queued, 2)
	got := sub.submitted()
	is.Equal(len(got), 2)
	for _, req := range got {
		// Each child records the index it came from, which is what lets a
		// workload matched by index digest resolve (ADR-044 tier two).
		is.Equal(req.IndexDigest, "sha256:index-digest")
		is.True(req.Digest != "sha256:index-digest")
		is.True(req.Digest != "sha256:attest")
	}
}

// TestSubmitForRunningImage_RegistryDeclines checks that the two configuration
// refusals stop here, at the function that would otherwise spend the
// registry's credentials, rather than being trusted from the caller.
func TestSubmitForRunningImage_RegistryDeclines(t *testing.T) {
	tests := []struct {
		name string
		reg  service.Registry
		repo string
	}{
		{
			name: "disabled registry",
			reg:  service.Registry{URL: "http://127.0.0.1:1", Enabled: false},
			repo: "myrepo",
		},
		{
			name: "repository excluded by patterns",
			reg: service.Registry{
				URL: "http://127.0.0.1:1", Enabled: true,
				RepositoryPatterns: []string{"allowed/*"},
			},
			repo: "myrepo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			sub := &fakeSubmitter{}
			// The URL points at a closed port: reaching the registry at all
			// would fail the test with an error rather than a silent zero.
			queued, err := SubmitForRunningImage(t.Context(), tt.reg, tt.repo, "sha256:whatever", "", sub, discardLogger())
			is.NoErr(err)
			is.Equal(queued, 0)
			is.Equal(len(sub.submitted()), 0)
		})
	}
}
