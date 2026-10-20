package scanner

import (
	"fmt"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

func TestPreviewRegistry(t *testing.T) {
	is := is.New(t)
	cfg := ociRegistryConfig{tags: map[string][]string{}}
	for i := range 30 {
		addImage(&cfg, fmt.Sprintf("1.%d.0", i), fmt.Sprintf("sha256:p%02d", i), "")
	}
	// The newest tag is a two-platform index, the sample the estimate uses.
	cfg.manifests["app:1.29.0"] = fakeManifest{
		digest: "sha256:idx", mediaType: "application/vnd.oci.image.index.v1+json",
		body: ociIndexManifest([]struct{ digest, arch string }{{"sha256:a", "amd64"}, {"sha256:b", "arm64"}}),
	}
	cfg.manifests["app:sha256:idx"] = cfg.manifests["app:1.29.0"]
	cfg.tags["app"] = append(cfg.tags["app"], "sha256-abc.sig", "latest") // attached artifact; filtered out by semver anyway
	srv := newFakeOCIRegistry(t, cfg)
	defer srv.Close()

	reg := service.Registry{URL: srv.URL, Repositories: []string{"app"}, TagPatterns: []string{"semver"}, TagLimit: 10}
	p, err := PreviewRegistry(t.Context(), reg, testEgress, discardLogger())
	is.NoErr(err)
	is.Equal(len(p.Repositories), 1)
	app := p.Repositories[0]
	is.Equal(app.Matched, 30)
	is.Equal(app.Selected, 10)
	is.Equal(app.SkippedByLimit, 20)
	is.Equal(app.Platforms, 2)
	is.Equal(app.EstimatedSBOMs, 20)
	is.Equal(p.EstimatedSBOMs, 20)
}
