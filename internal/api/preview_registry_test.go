package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/netguard"
	"github.com/pfenerty/ocidex/internal/scanner"
)

// previewOCIRegistry serves one repository, "app", with three semver tags,
// each a single-arch image.
func previewOCIRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/app/tags/list":
			_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"1.0.0", "1.1.0", "1.2.0"}})
		case strings.HasPrefix(r.URL.Path, "/v2/app/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", "sha256:"+strings.TrimPrefix(r.URL.Path, "/v2/app/manifests/"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestPreviewRegistryConfig covers ocidex-5y0r.2: an unsaved config previews
// its window and nothing is created or queued. The handler has no scan
// submitter at all, so a preview cannot reach one.
func TestPreviewRegistryConfig(t *testing.T) {
	srv := previewOCIRegistry(t)
	host := strings.TrimPrefix(srv.URL, "http://")
	regSvc := &recordingRegistryService{}
	cfg := &config.Config{EgressPolicy: netguard.Policy{AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}
	h := api.NewHandler(nil, nil, createRegistryAuthService(), regSvc, &namedNamespaceService{}, nil, nil, nil, nil, nil, &fakePinger{}, nil, cfg)
	router := api.NewRouter(h, "*", "", "")

	t.Run("counts", func(t *testing.T) {
		is := is.New(t)
		body := fmt.Sprintf(`{"type":"generic","url":%q,"insecure":true,"repositories":["app"],"tag_patterns":["semver"],"tag_limit":2}`, host)
		w := memberRequest(router, http.MethodPost, "/api/v1/registries/preview", body, "stranger-token")
		is.Equal(w.Code, http.StatusOK)
		var p scanner.RegistryPreview
		is.NoErr(json.Unmarshal(w.Body.Bytes(), &p))
		is.Equal(len(p.Repositories), 1)
		is.Equal(p.Repositories[0].Matched, 3)
		is.Equal(p.Selected, 2)
		is.Equal(p.SkippedByLimit, 1)
		is.Equal(p.EstimatedSBOMs, 2)
		is.Equal(len(regSvc.calls), 0) // nothing saved
	})

	t.Run("invalid window is a 400", func(t *testing.T) {
		is := is.New(t)
		body := fmt.Sprintf(`{"type":"generic","url":%q,"insecure":true,"tag_patterns":["semver"],"max_tag_age_days":30}`, host)
		w := memberRequest(router, http.MethodPost, "/api/v1/registries/preview", body, "stranger-token")
		is.Equal(w.Code, http.StatusBadRequest)
	})
}
