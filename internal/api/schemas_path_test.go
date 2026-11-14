package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSchemaLinksUnderAPIPrefix: every deployment routes only /api, /auth,
// /health and /ready to the API, so the "$schema" a body carries and the Link
// an error carries must point under /api to resolve at all (ocidex-m3yn).
func TestSchemaLinksUnderAPIPrefix(t *testing.T) {
	h := newTestHandlerWithPinger(&fakeSBOMService{}, &fakeSearchService{}, &fakePinger{})
	r := newTestRouterFromHandler(h)

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	// An error body: its $schema and its Link header.
	rec := get("/api/v1/clusters/00000000-0000-0000-0000-000000000000")
	var body struct {
		Schema string `json:"$schema"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %d body: %v", rec.Code, err)
	}
	if !strings.Contains(body.Schema, "/api/schemas/ErrorModel.json") {
		t.Errorf("$schema = %q, want it under /api/schemas", body.Schema)
	}
	if link := rec.Header().Get("Link"); !strings.Contains(link, "</api/schemas/ErrorModel.json>") {
		t.Errorf("Link = %q, want it under /api/schemas", link)
	}

	// The link resolves, and refers onward under the same prefix.
	s := get("/api/schemas/ErrorModel.json")
	if s.Code != http.StatusOK || !strings.Contains(s.Body.String(), `"properties"`) {
		t.Fatalf("GET /api/schemas/ErrorModel.json = %d", s.Code)
	}
	if strings.Contains(s.Body.String(), `"/schemas/`) {
		t.Error("schema body still references /schemas/")
	}

	// The old spelling redirects rather than 404ing.
	old := get("/schemas/ErrorModel.json")
	if old.Code != http.StatusMovedPermanently || old.Header().Get("Location") != "/api/schemas/ErrorModel.json" {
		t.Errorf("GET /schemas/ErrorModel.json = %d -> %q", old.Code, old.Header().Get("Location"))
	}

	// A name that isn't a schema file name is refused, not echoed into Location.
	if bad := get("/schemas/a%2F%2Fevil.example"); bad.Code != http.StatusNotFound {
		t.Errorf("GET /schemas/<odd name> = %d -> %q, want 404", bad.Code, bad.Header().Get("Location"))
	}
}
