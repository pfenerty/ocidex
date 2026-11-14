package api_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/api"
)

func apiRefRouter(t *testing.T) http.Handler {
	t.Helper()
	h := newTestHandlerWithPinger(&fakeSBOMService{}, &fakeSearchService{}, &fakePinger{})
	return newTestRouterFromHandler(h)
}

func apiRefGet(t *testing.T, r http.Handler, path string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// TestAPIReferencePage pins the parts of /api/docs that are a promise rather
// than a style: it is reachable under /api, the CSP keeps the page talking only
// to this server, and Scalar's phone-home features are switched off.
func TestAPIReferencePage(t *testing.T) {
	r := apiRefRouter(t)
	rec := apiRefGet(t, r, "/api/docs", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/docs = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "default-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}

	body := rec.Body.String()
	if !strings.Contains(body, `data-url="/api/openapi.json"`) {
		t.Error("page does not load the /api copy of the spec")
	}
	m := regexp.MustCompile(`data-configuration="([^"]*)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no data-configuration attribute")
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &cfg); err != nil {
		t.Fatalf("configuration is not JSON: %v", err)
	}
	if cfg["hideClientButton"] != true {
		t.Error("hideClientButton must stay true: the button opens client.scalar.com")
	}
	if cfg["telemetry"] != false || cfg["withDefaultFonts"] != false {
		t.Errorf("telemetry/withDefaultFonts not disabled: %v / %v", cfg["telemetry"], cfg["withDefaultFonts"])
	}
	for _, k := range []string{"agent", "mcp"} {
		sub, _ := cfg[k].(map[string]any)
		if sub["disabled"] != true {
			t.Errorf("%s not disabled: %v", k, cfg[k])
		}
	}
}

// TestAPIReferenceOriginServer: with no API_BASE_URL the spec carries no
// servers block, so the page has init.js point Scalar at the browser's origin;
// with one, the spec's servers block stands and the page leaves it alone.
func TestAPIReferenceOriginServer(t *testing.T) {
	for _, tc := range []struct {
		base string
		want string
	}{{"", `data-origin-server="true"`}, {"https://ocidex.example", `data-origin-server="false"`}} {
		h := newTestHandlerWithPinger(&fakeSBOMService{}, &fakeSearchService{}, &fakePinger{})
		r := api.NewRouter(h, "*", "", tc.base)
		body := apiRefGet(t, r, "/api/docs", nil).Body.String()
		if !strings.Contains(body, tc.want) {
			t.Errorf("API_BASE_URL=%q: page lacks %s", tc.base, tc.want)
		}
		if strings.Index(body, `src="/api/docs/init.js"`) > strings.Index(body, `src="/api/docs/scalar.js`) {
			t.Errorf("init.js must load before the renderer, which reads its configuration on load")
		}
	}
	js := apiRefGet(t, apiRefRouter(t), "/api/docs/init.js", nil)
	if js.Code != http.StatusOK || !strings.Contains(js.Body.String(), "window.location.origin") {
		t.Errorf("GET /api/docs/init.js = %d", js.Code)
	}
}

func TestAPIReferenceRedirects(t *testing.T) {
	r := apiRefRouter(t)
	for _, p := range []string{"/docs", "/api/docs/"} {
		rec := apiRefGet(t, r, p, nil)
		if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/api/docs" {
			t.Errorf("GET %s = %d -> %q, want 301 -> /api/docs", p, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestAPIReferenceScript(t *testing.T) {
	r := apiRefRouter(t)

	gz := apiRefGet(t, r, "/api/docs/scalar.js", map[string]string{"Accept-Encoding": "br, gzip"})
	if gz.Code != http.StatusOK || gz.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("gzip request = %d, Content-Encoding %q", gz.Code, gz.Header().Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz.Body.Bytes()))
	if err != nil {
		t.Fatalf("body is not gzip: %v", err)
	}
	inflated, _ := io.ReadAll(zr)

	plain := apiRefGet(t, r, "/api/docs/scalar.js", nil)
	if plain.Header().Get("Content-Encoding") != "" {
		t.Errorf("identity request got Content-Encoding %q", plain.Header().Get("Content-Encoding"))
	}
	if !bytes.Equal(plain.Body.Bytes(), inflated) || len(inflated) < 1<<20 {
		t.Errorf("identity body (%d bytes) differs from inflated gzip body (%d bytes)", plain.Body.Len(), len(inflated))
	}
}

// TestAPISpecUnderAPIPrefix checks that the /api copies of the spec are the
// same document huma serves at /openapi.json, which pkg/client still reads.
func TestAPISpecUnderAPIPrefix(t *testing.T) {
	r := apiRefRouter(t)
	root := apiRefGet(t, r, "/openapi.json", nil)
	prefixed := apiRefGet(t, r, "/api/openapi.json", nil)
	if root.Code != http.StatusOK || prefixed.Code != http.StatusOK {
		t.Fatalf("/openapi.json = %d, /api/openapi.json = %d", root.Code, prefixed.Code)
	}
	var a, b any
	if err := json.Unmarshal(root.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(prefixed.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Error("/api/openapi.json differs from /openapi.json")
	}

	y := apiRefGet(t, r, "/api/openapi.yaml", nil)
	if y.Code != http.StatusOK || !strings.Contains(y.Body.String(), "openapi: 3.1") {
		t.Errorf("/api/openapi.yaml = %d, starts %q", y.Code, firstLine(y.Body.String()))
	}
}

// TestOpenAPITagsAreDescribed keeps every operation group in the reference
// headed by a description: a new tag without one would render as a bare name.
func TestOpenAPITagsAreDescribed(t *testing.T) {
	h := newTestHandlerWithPinger(&fakeSBOMService{}, &fakeSearchService{}, &fakePinger{})
	_ = newTestRouterFromHandler(h)
	spec := h.API().OpenAPI()

	described := map[string]bool{}
	for _, tag := range spec.Tags {
		described[tag.Name] = strings.TrimSpace(tag.Description) != ""
	}
	used := map[string]bool{}
	for path, item := range spec.Paths {
		for _, op := range []*huma.Operation{item.Get, item.Put, item.Post, item.Delete, item.Patch, item.Head, item.Options} {
			if op == nil {
				continue
			}
			for _, tag := range op.Tags {
				used[tag] = true
				if !described[tag] {
					t.Errorf("%s %s uses tag %q, which has no description in apiTags", op.Method, path, tag)
				}
			}
		}
	}
	for name := range described {
		if !used[name] {
			t.Errorf("apiTags declares %q, which no operation uses", name)
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
