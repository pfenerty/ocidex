package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
	"github.com/pfenerty/ocidex/internal/service"
)

type fakeSearchService struct{}

func (f *fakeSearchService) GetSBOM(_ context.Context, _ pgtype.UUID, _ bool, _ service.VisibilityFilter) (service.SBOMDetail, error) {
	return service.SBOMDetail{
		SBOMSummary: service.SBOMSummary{
			ID:          "3e671687-395b-41f5-a30f-a58921a69b79",
			SpecVersion: "1.5",
			Version:     1,
			CreatedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}, nil
}

func (f *fakeSearchService) ListSBOMs(_ context.Context, _ service.SBOMFilter) (service.CursorPage[service.SBOMSummary], error) {
	return service.CursorPage[service.SBOMSummary]{
		Data:    []service.SBOMSummary{{ID: "abc", SpecVersion: "1.5", Version: 1, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}},
		HasMore: false,
	}, nil
}

func (f *fakeSearchService) SearchComponents(_ context.Context, filter service.ComponentFilter) (service.PagedResult[service.ComponentSummary], error) {
	return service.PagedResult[service.ComponentSummary]{
		Data:   []service.ComponentSummary{{ID: "comp1", Name: filter.Name, Type: "library"}},
		Total:  1,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (f *fakeSearchService) GetComponent(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) (service.ComponentDetail, error) {
	return service.ComponentDetail{
		ComponentSummary: service.ComponentSummary{ID: "comp1", Name: "test-lib", Type: "library"},
		Hashes:           []service.HashEntry{},
		Licenses:         []service.LicenseSummary{},
		ExternalRefs:     []service.ExternalRefEntry{},
	}, nil
}

func (f *fakeSearchService) ListLicenses(_ context.Context, filter service.LicenseFilter) (service.PagedResult[service.LicenseCount], error) {
	mit := "MIT"
	return service.PagedResult[service.LicenseCount]{
		Data:   []service.LicenseCount{{ID: "lic1", SpdxID: &mit, Name: "MIT License", ComponentCount: 10, Category: "permissive"}},
		Total:  1,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (f *fakeSearchService) ListComponentsByLicense(_ context.Context, _ pgtype.UUID, limit, offset int32, _ service.VisibilityFilter) (service.PagedResult[service.ComponentSummary], error) {
	return service.PagedResult[service.ComponentSummary]{
		Data:   []service.ComponentSummary{{ID: "comp1", Name: "test-lib", Type: "library"}},
		Total:  1,
		Limit:  limit,
		Offset: offset,
	}, nil
}

func (f *fakeSearchService) GetArtifact(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) (service.ArtifactDetail, error) {
	return service.ArtifactDetail{
		ArtifactSummary: service.ArtifactSummary{ID: "art1", Type: "container", Name: "ubuntu", SbomCount: 2},
		CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

func (f *fakeSearchService) ListArtifacts(_ context.Context, _ service.ArtifactFilter) (service.CursorPage[service.ArtifactSummary], error) {
	return service.CursorPage[service.ArtifactSummary]{
		Data: []service.ArtifactSummary{{ID: "art1", Type: "container", Name: "ubuntu", SbomCount: 2}},
	}, nil
}

func (f *fakeSearchService) ListSBOMsByArtifact(_ context.Context, _ pgtype.UUID, _, _ string, _ service.SBOMByArtifactPage, _ service.VisibilityFilter) (service.CursorPage[service.SBOMSummary], error) {
	return service.CursorPage[service.SBOMSummary]{
		Data: []service.SBOMSummary{{ID: "sbom1", SpecVersion: "1.5", Version: 1, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}},
	}, nil
}

func (f *fakeSearchService) GetArtifactChangelog(_ context.Context, _ pgtype.UUID, _, _, _ string, _ service.VersionSortMode, _ service.VisibilityFilter) (service.Changelog, error) {
	return service.Changelog{
		ArtifactID: "art1",
		Entries:    []service.ChangelogEntry{},
	}, nil
}

func (f *fakeSearchService) ListSBOMsByDigest(_ context.Context, _ string, limit, offset int32, _ service.VisibilityFilter) (service.PagedResult[service.SBOMSummary], error) {
	d := "sha256:abc123"
	return service.PagedResult[service.SBOMSummary]{
		Data:   []service.SBOMSummary{{ID: "sbom1", SpecVersion: "1.5", Version: 1, Digest: &d, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}},
		Total:  1,
		Limit:  limit,
		Offset: offset,
	}, nil
}

func (f *fakeSearchService) DiffSBOMs(_ context.Context, _, _ pgtype.UUID, _ service.VisibilityFilter) (service.ChangelogEntry, error) {
	return service.ChangelogEntry{
		From:    service.SBOMRef{ID: "from1"},
		To:      service.SBOMRef{ID: "to1"},
		Summary: service.ChangeSummary{Added: 1},
		Changes: []service.ComponentDiff{{Type: "added", Name: "new-pkg"}},
	}, nil
}

func (f *fakeSearchService) DiffSBOMsWithTree(_ context.Context, _, _ pgtype.UUID, _ service.VisibilityFilter) (service.DiffTree, error) {
	return service.DiffTree{
		From:    service.SBOMRef{ID: "from1"},
		To:      service.SBOMRef{ID: "to1"},
		Summary: service.ChangeSummary{Added: 1},
		Changes: []service.ComponentDiff{{Type: "added", Name: "new-pkg"}},
		Nodes:   []service.ComponentSummary{},
		Edges:   []service.DependencyEdge{},
	}, nil
}

func (f *fakeSearchService) GetArtifactLicenseSummary(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) ([]service.LicenseCount, error) {
	mit := "MIT"
	return []service.LicenseCount{
		{ID: "lic1", SpdxID: &mit, Name: "MIT License", ComponentCount: 42, Category: "permissive"},
	}, nil
}

func (f *fakeSearchService) GetSBOMDependencies(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) (service.DependencyGraph, error) {
	return service.DependencyGraph{
		Nodes: []service.ComponentSummary{{ID: "comp1", Name: "test-lib", Type: "library"}},
		Edges: []service.DependencyEdge{{From: "ref-a", To: "ref-b"}},
	}, nil
}

func (f *fakeSearchService) SearchDistinctComponents(_ context.Context, filter service.ComponentFilter) (service.PagedResult[service.DistinctComponentSummary], error) {
	return service.PagedResult[service.DistinctComponentSummary]{
		Data:   []service.DistinctComponentSummary{{Name: filter.Name, Type: "library", VersionCount: 3, SbomCount: 5}},
		Total:  1,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (f *fakeSearchService) GetComponentVersions(_ context.Context, name, _, _, _ string, _ service.VisibilityFilter) ([]service.ComponentVersionEntry, error) {
	return []service.ComponentVersionEntry{
		{ID: "comp1", SbomID: "sbom1", Type: "library", Name: name, SbomCreatedAt: "2025-01-01T00:00:00Z"},
	}, nil
}

func (f *fakeSearchService) ListSBOMComponents(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) ([]service.ComponentSummary, error) {
	return []service.ComponentSummary{
		{ID: "comp1", SbomID: "sbom1", Name: "test-lib", Type: "library"},
	}, nil
}

func (f *fakeSearchService) ListSBOMComponentsPage(_ context.Context, _ pgtype.UUID, _ service.ComponentPage, _ service.VisibilityFilter) (service.CursorPage[service.ComponentSummary], error) {
	return service.CursorPage[service.ComponentSummary]{
		Data: []service.ComponentSummary{{ID: "comp1", SbomID: "sbom1", Name: "test-lib", Type: "library"}},
	}, nil
}

func (f *fakeSearchService) ListComponentPurlTypes(_ context.Context, _ service.VisibilityFilter) ([]string, error) {
	return []string{"apk", "deb", "golang", "npm", "rpm"}, nil
}

func (f *fakeSearchService) GetDashboardStats(_ context.Context, _ service.VisibilityFilter) (*service.DashboardStats, error) {
	return &service.DashboardStats{}, nil
}

func (f *fakeSearchService) WarmDashboardStats(_ context.Context, _ service.VisibilityFilter) (*service.DashboardStats, error) {
	return &service.DashboardStats{}, nil
}

func (f *fakeSearchService) ListVersionsByArtifact(_ context.Context, _ pgtype.UUID, limit, offset int32, _ service.VersionSortMode, _ service.VisibilityFilter) (service.ArtifactVersionsPage, error) {
	return service.ArtifactVersionsPage{
		PagedResult: service.PagedResult[service.ArtifactVersion]{
			Data:   []service.ArtifactVersion{{VersionKey: "v1.0.0", SbomID: "sbom1", Architectures: []string{"amd64"}}},
			Total:  1,
			Limit:  limit,
			Offset: offset,
		},
		HasSemver:    true,
		ResolvedMode: service.SortSemver,
	}, nil
}

func (f *fakeSearchService) ListTopVulnerabilities(_ context.Context, filter service.TopVulnFilter) (service.PagedResult[service.TopVulnEntry], error) {
	return service.PagedResult[service.TopVulnEntry]{Data: []service.TopVulnEntry{}, Limit: filter.Limit, Offset: filter.Offset}, nil
}

func (f *fakeSearchService) GetArtifactVulnSummary(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) (*service.VulnSummary, error) {
	return nil, nil
}

func (f *fakeSearchService) GetArtifactUsages(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) ([]service.ArtifactRelation, error) {
	return nil, nil
}

func (f *fakeSearchService) GetArtifactContains(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) ([]service.ArtifactRelation, error) {
	return nil, nil
}

func (f *fakeSearchService) GetVulnerabilityDetail(_ context.Context, _ string, limit, offset int32, _ service.VisibilityFilter) (*service.VulnDetail, service.PagedResult[service.AffectedArtifact], service.PagedResult[service.AffectedComponent], error) {
	return &service.VulnDetail{ID: "CVE-2021-0001", Severity: "HIGH", Aliases: []string{}}, service.PagedResult[service.AffectedArtifact]{Limit: limit, Offset: offset}, service.PagedResult[service.AffectedComponent]{}, nil
}

func (f *fakeSearchService) GetComponentVulns(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) ([]service.ComponentVulnEntry, error) {
	return []service.ComponentVulnEntry{}, nil
}

func (f *fakeSearchService) ListSBOMDriftHistory(_ context.Context, _ pgtype.UUID, _ service.DriftPage, _ service.VisibilityFilter) (service.CursorPage[service.ProvenanceDriftSummary], error) {
	return service.CursorPage[service.ProvenanceDriftSummary]{}, nil
}

func (f *fakeSearchService) ListRecentProvenanceDrift(_ context.Context, _ service.DriftPage, _ service.VisibilityFilter) (service.CursorPage[service.RecentDriftEntry], error) {
	return service.CursorPage[service.RecentDriftEntry]{}, nil
}

func (f *fakeSearchService) ListOwnedActivity(_ context.Context, _ pgtype.UUID, _ service.FeedPage) (service.CursorPage[service.ActivityEntry], error) {
	return service.CursorPage[service.ActivityEntry]{}, nil
}

func (f *fakeSearchService) LookupArtifact(_ context.Context, _ service.ArtifactLookupQuery, _ service.VisibilityFilter) ([]service.LookupCandidate, error) {
	return []service.LookupCandidate{
		{ID: "3e671687-395b-41f5-a30f-a58921a69b79", Qualifiers: map[string]string{"name": "ubuntu", "type": "container", "group": ""}},
	}, nil
}

func (f *fakeSearchService) LookupSBOM(_ context.Context, _ service.SBOMLookupQuery, _ service.VisibilityFilter) ([]service.LookupCandidate, error) {
	return []service.LookupCandidate{
		{ID: "3e671687-395b-41f5-a30f-a58921a69b79", Qualifiers: map[string]string{"artifact": "ubuntu", "version": "1.0"}},
	}, nil
}

// LookupLicense knows one license, so tests get both a hit and a miss without
// a dedicated fake.
func (f *fakeSearchService) LookupLicense(_ context.Context, spdxID string, _ service.VisibilityFilter) (service.LicenseCount, error) {
	if spdxID != "MIT" {
		return service.LicenseCount{}, service.ErrNotFound
	}
	mit := "MIT"
	return service.LicenseCount{ID: "lic1", SpdxID: &mit, Name: "MIT License", ComponentCount: 10, Category: "permissive"}, nil
}

// notFoundSearchService returns ErrNotFound for single-item lookups.
type notFoundSearchService struct{ fakeSearchService }

func (f *notFoundSearchService) GetSBOM(_ context.Context, _ pgtype.UUID, _ bool, _ service.VisibilityFilter) (service.SBOMDetail, error) {
	return service.SBOMDetail{}, service.ErrNotFound
}

func (f *notFoundSearchService) GetComponent(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) (service.ComponentDetail, error) {
	return service.ComponentDetail{}, service.ErrNotFound
}

func (f *notFoundSearchService) GetArtifact(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) (service.ArtifactDetail, error) {
	return service.ArtifactDetail{}, service.ErrNotFound
}

func (f *notFoundSearchService) GetComponentVulns(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) ([]service.ComponentVulnEntry, error) {
	return nil, service.ErrNotFound
}

// cursorBody is a helper for decoding keyset-paginated JSON responses.
type cursorBody struct {
	Data       json.RawMessage `json:"data"`
	Pagination struct {
		Limit      int32   `json:"limit"`
		HasMore    bool    `json:"hasMore"`
		NextCursor *string `json:"nextCursor"`
	} `json:"pagination"`
}

func TestListSBOMs(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms?limit=10", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)

	var resp cursorBody
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
	is.Equal(resp.Pagination.Limit, int32(10))
	is.Equal(resp.Pagination.HasMore, false)
}

func TestGetSBOM(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		search     service.SearchService
		wantStatus int
	}{
		{"found", "3e671687-395b-41f5-a30f-a58921a69b79", &fakeSearchService{}, http.StatusOK},
		{"not found", "3e671687-395b-41f5-a30f-a58921a69b79", &notFoundSearchService{}, http.StatusNotFound},
		{"bad uuid", "not-a-uuid", &fakeSearchService{}, http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, tt.search)

			r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/"+tt.id, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestSearchComponents(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantStatus int
	}{
		{"with name", "?name=lodash", http.StatusOK},
		{"with purl", "?purl=pkg:npm/lodash@4.17.21", http.StatusOK},
		{"with both", "?name=lodash&purl=pkg:npm/lodash@4.17.21", http.StatusOK},
		// Neither key means an unbounded scan, so it is rejected rather than served.
		{"neither name nor purl", "", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

			r := httptest.NewRequest(http.MethodGet, "/api/v1/components"+tt.query, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

// capturingSearchService records the ComponentFilter it was handed so a test
// can assert the query string reached the service unmangled.
type capturingSearchService struct {
	fakeSearchService
	filter service.ComponentFilter
}

func (f *capturingSearchService) SearchComponents(_ context.Context, filter service.ComponentFilter) (service.PagedResult[service.ComponentSummary], error) {
	f.filter = filter
	return service.PagedResult[service.ComponentSummary]{Limit: filter.Limit, Offset: filter.Offset}, nil
}

func TestSearchComponentsPassesPurlThrough(t *testing.T) {
	is := is.New(t)
	search := &capturingSearchService{}
	router := newTestRouter(&fakeSBOMService{}, search)

	// The purl's own '@' and '/' must survive query decoding intact — they are
	// part of the key, not separators.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/components?purl="+url.QueryEscape("pkg:npm/@scope/lodash@4.17.21"), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)
	is.Equal(search.filter.Purl, "pkg:npm/@scope/lodash@4.17.21")
	is.Equal(search.filter.Name, "")
}

func TestGetComponent(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		search     service.SearchService
		wantStatus int
	}{
		{"found", "3e671687-395b-41f5-a30f-a58921a69b79", &fakeSearchService{}, http.StatusOK},
		{"not found", "3e671687-395b-41f5-a30f-a58921a69b79", &notFoundSearchService{}, http.StatusNotFound},
		{"bad uuid", "invalid", &fakeSearchService{}, http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, tt.search)

			r := httptest.NewRequest(http.MethodGet, "/api/v1/components/"+tt.id, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestListLicenses(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/licenses?spdx_id=MIT", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)
}

func TestListComponentsByLicense(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/licenses/3e671687-395b-41f5-a30f-a58921a69b79/components", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)
}

func TestListArtifacts(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?type=container", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)

	var resp cursorBody
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
	is.Equal(resp.Pagination.HasMore, false)
	is.Equal(string(resp.Data), `[{"id":"art1","type":"container","name":"ubuntu","sbomCount":2,"sufficientSbomCount":0,"signingStatus":""}]`)
}

func TestGetArtifact(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		search     service.SearchService
		wantStatus int
	}{
		{"found", "3e671687-395b-41f5-a30f-a58921a69b79", &fakeSearchService{}, http.StatusOK},
		{"not found", "3e671687-395b-41f5-a30f-a58921a69b79", &notFoundSearchService{}, http.StatusNotFound},
		{"bad uuid", "invalid", &fakeSearchService{}, http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, tt.search)

			r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/"+tt.id, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestListArtifactSBOMs(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/3e671687-395b-41f5-a30f-a58921a69b79/sboms", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)

	var resp cursorBody
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
	is.Equal(resp.Pagination.HasMore, false)
}

func TestGetArtifactChangelog(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		wantStatus int
	}{
		{"valid uuid", "3e671687-395b-41f5-a30f-a58921a69b79", http.StatusOK},
		{"bad uuid", "invalid", http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

			r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/"+tt.id+"/changelog", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestGetSBOMDependencies(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		wantStatus int
	}{
		{"valid", "3e671687-395b-41f5-a30f-a58921a69b79", http.StatusOK},
		{"bad uuid", "invalid", http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

			r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/"+tt.id+"/dependencies", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestGetDashboardStats(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)

	var body struct {
		VulnCount    int64 `json:"vuln_count"`
		VulnSeverity struct {
			Critical int64 `json:"critical"`
			High     int64 `json:"high"`
			Medium   int64 `json:"medium"`
			Low      int64 `json:"low"`
			Unknown  int64 `json:"unknown"`
		} `json:"vuln_severity"`
	}
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &body))
	// fakeSearchService returns zero-valued DashboardStats; fields must be present
	is.Equal(body.VulnCount, int64(0))
	is.Equal(body.VulnSeverity.Critical, int64(0))
	is.Equal(body.VulnSeverity.High, int64(0))
	is.Equal(body.VulnSeverity.Medium, int64(0))
	is.Equal(body.VulnSeverity.Low, int64(0))
	is.Equal(body.VulnSeverity.Unknown, int64(0))
}

func TestGetArtifactLicenseSummary(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		wantStatus int
	}{
		{"valid", "3e671687-395b-41f5-a30f-a58921a69b79", http.StatusOK},
		{"bad uuid", "invalid", http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

			r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/"+tt.id+"/license-summary", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestDiffSBOMs(t *testing.T) {
	validID := "3e671687-395b-41f5-a30f-a58921a69b79"
	tests := []struct {
		name       string
		query      string
		wantStatus int
	}{
		{"valid", "?from=" + validID + "&to=" + validID, http.StatusOK},
		{"missing from", "?to=" + validID, http.StatusUnprocessableEntity},
		{"missing to", "?from=" + validID, http.StatusUnprocessableEntity},
		{"missing both", "", http.StatusUnprocessableEntity},
		{"bad from uuid", "?from=invalid&to=" + validID, http.StatusUnprocessableEntity},
		{"bad to uuid", "?from=" + validID + "&to=invalid", http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

			r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/diff"+tt.query, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}
