package scanner

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

const mtImage = "application/vnd.oci.image.manifest.v1+json"

// addImage registers a single-arch image in repo "app" under a tag (and under its digest, as
// ociGetImageMetadata fetches it) with an optional build date.
func addImage(cfg *ociRegistryConfig, tag, digest, created string) {
	const repo = "app"
	if cfg.manifests == nil {
		cfg.manifests = map[string]fakeManifest{}
		cfg.blobs = map[string][]byte{}
	}
	m := fakeManifest{digest: digest, mediaType: mtImage, body: singleArchManifest("cfg-" + digest)}
	if tag != "" {
		cfg.manifests[repo+":"+tag] = m
		cfg.tags[repo] = append(cfg.tags[repo], tag)
	}
	cfg.manifests[repo+":"+digest] = m
	blob := map[string]any{"architecture": "amd64"}
	if created != "" {
		blob["created"] = created
	}
	cfg.blobs["cfg-"+digest], _ = json.Marshal(blob)
}

func submittedTags(sub *fakeSubmitter) []string {
	reqs := sub.submitted()
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Tag)
	}
	slices.Sort(out)
	return out
}

// TestWalkRegistry_TagLimitWindow is ADR-0053's confirmation case: 200 semver
// tags with tag_limit 10 queue the newest 10, and once those SBOMs are gone a
// second walk queues the same 10 again and nothing from outside the window.
func TestWalkRegistry_TagLimitWindow(t *testing.T) {
	is := is.New(t)
	cfg := ociRegistryConfig{tags: map[string][]string{}}
	for i := range 200 {
		addImage(&cfg, fmt.Sprintf("v1.%d.0", i), fmt.Sprintf("sha256:d%03d", i), "")
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	reg := service.Registry{URL: srv.URL, Repositories: []string{"app"}, TagPatterns: []string{"semver"}, TagLimit: 10}
	var want []string
	for i := 190; i < 200; i++ {
		want = append(want, fmt.Sprintf("v1.%d.0", i))
	}
	slices.Sort(want)

	sub := &fakeSubmitter{}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, testEgress, discardLogger())
	is.NoErr(err)
	is.Equal(queued, 10)
	is.Equal(submittedTags(sub), want)

	// Already ingested: the window keeps its slots and queues nothing new.
	known := map[string]bool{}
	for _, r := range sub.submitted() {
		known[r.Digest] = true
	}
	sub2 := &fakeSubmitter{}
	queued, err = WalkRegistry(t.Context(), reg, sub2, known, testEgress, discardLogger())
	is.NoErr(err)
	is.Equal(queued, 0)

	// SBOMs deleted out of band: only the window comes back.
	sub3 := &fakeSubmitter{}
	queued, err = WalkRegistry(t.Context(), reg, sub3, nil, testEgress, discardLogger())
	is.NoErr(err)
	is.Equal(queued, 10)
	is.Equal(submittedTags(sub3), want)
}

func TestWalkRegistry_AttachedArtifactTagsTakeNoSlot(t *testing.T) {
	is := is.New(t)
	cfg := ociRegistryConfig{tags: map[string][]string{}}
	addImage(&cfg, "zzz", "sha256:img", "2026-10-01T00:00:00Z")
	addImage(&cfg, "sha256-abc.sig", "sha256:sig", "2026-10-02T00:00:00Z")
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL, Repositories: []string{"app"}, TagOrder: service.TagOrderLexical, TagLimit: 1}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, testEgress, discardLogger())
	is.NoErr(err)
	is.Equal(queued, 1)
	is.Equal(submittedTags(sub), []string{"zzz"})
}

func TestWalkRegistry_CreatedOrder(t *testing.T) {
	is := is.New(t)
	day := func(d int) string { return time.Now().AddDate(0, 0, -d).UTC().Format(time.RFC3339) }
	cfg := ociRegistryConfig{tags: map[string][]string{}}
	addImage(&cfg, "old", "sha256:c-old", day(60))
	addImage(&cfg, "mid", "sha256:c-mid", day(10))
	addImage(&cfg, "new", "sha256:c-new", day(1))
	addImage(&cfg, "undated", "sha256:c-undated", "")
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	// No patterns and no order: auto resolves to created.
	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL, Repositories: []string{"app"}, TagLimit: 2}
	_, err := WalkRegistry(t.Context(), reg, sub, nil, testEgress, discardLogger())
	is.NoErr(err)
	is.Equal(submittedTags(sub), []string{"mid", "new"})

	sub = &fakeSubmitter{}
	reg.TagLimit, reg.MaxTagAgeDays = 0, 30
	_, err = WalkRegistry(t.Context(), reg, sub, nil, testEgress, discardLogger())
	is.NoErr(err)
	is.Equal(submittedTags(sub), []string{"mid", "new"}) // old is past the cutoff, undated cannot be shown inside it
}

func TestWalkRegistry_UntaggedWindow(t *testing.T) {
	is := is.New(t)
	cfg := ociRegistryConfig{tags: map[string][]string{"app": {}}}
	addImage(&cfg, "", "sha256:u-old", "2026-01-01T00:00:00Z")
	addImage(&cfg, "", "sha256:u-new", "2026-10-01T00:00:00Z")
	addImage(&cfg, "", "sha256:tagged", "2026-10-02T00:00:00Z")
	cfg.zotResults = []DiscoveredManifest{
		{Digest: "sha256:u-old", MediaType: mtImage},
		{Digest: "sha256:u-new", MediaType: mtImage},
		// Tagged, but outside the tag window (no tags/list entry): must not slip in here.
		{Digest: "sha256:tagged", MediaType: mtImage, Tag: "v0.0.1"},
	}
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	sub := &fakeSubmitter{}
	reg := service.Registry{URL: srv.URL, Type: "zot", Repositories: []string{"app"}, IncludeUntagged: true, TagLimit: 1}
	queued, err := WalkRegistry(t.Context(), reg, sub, nil, testEgress, discardLogger())
	is.NoErr(err)
	is.Equal(queued, 1)
	is.Equal(sub.submitted()[0].Digest, "sha256:u-new")
}
