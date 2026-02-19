package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
	"github.com/pfenerty/ocidex/internal/service"
)

type fakeSearchService struct{}

func (f *fakeSearchService) GetSBOM(_ context.Context, _ pgtype.UUID, _ bool) (service.SBOMDetail, error) {
	return service.SBOMDetail{
		SBOMSummary: service.SBOMSummary{
			ID:          "3e671687-395b-41f5-a30f-a58921a69b79",
			SpecVersion: "1.5",
			Version:     1,
			CreatedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}, nil
}

func (f *fakeSearchService) ListSBOMs(_ context.Context, filter service.SBOMFilter) (service.PagedResult[service.SBOMSummary], error) {
	return service.PagedResult[service.SBOMSummary]{
		Data:   []service.SBOMSummary{{ID: "abc", SpecVersion: "1.5", Version: 1, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}},
		Total:  1,
		Limit:  filter.Limit,
		Offset: filter.Offset,
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

func (f *fakeSearchService) GetComponent(_ context.Context, _ pgtype.UUID) (service.ComponentDetail, error) {
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

func (f *fakeSearchService) ListComponentsByLicense(_ context.Context, _ pgtype.UUID, limit, offset int32) (service.PagedResult[service.ComponentSummary], error) {
	return service.PagedResult[service.ComponentSummary]{
		Data:   []service.ComponentSummary{{ID: "comp1", Name: "test-lib", Type: "library"}},
		Total:  1,
		Limit:  limit,
		Offset: offset,
	}, nil
}

func (f *fakeSearchService) GetArtifact(_ context.Context, _ pgtype.UUID) (service.ArtifactDetail, error) {
	return service.ArtifactDetail{
		ArtifactSummary: service.ArtifactSummary{ID: "art1", Type: "container", Name: "ubuntu", SbomCount: 2},
		CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

func (f *fakeSearchService) ListArtifacts(_ context.Context, filter service.ArtifactFilter) (service.PagedResult[service.ArtifactSummary], error) {
	return service.PagedResult[service.ArtifactSummary]{
		Data:   []service.ArtifactSummary{{ID: "art1", Type: "container", Name: "ubuntu", SbomCount: 2}},
		Total:  1,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (f *fakeSearchService) ListSBOMsByArtifact(_ context.Context, _ pgtype.UUID, _ string, limit, offset int32) (service.PagedResult[service.SBOMSummary], error) {
	return service.PagedResult[service.SBOMSummary]{
		Data:   []service.SBOMSummary{{ID: "sbom1", SpecVersion: "1.5", Version: 1, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}},
		Total:  1,
		Limit:  limit,
		Offset: offset,
	}, nil
}

func (f *fakeSearchService) GetArtifactChangelog(_ context.Context, _ pgtype.UUID, _ string) (service.Changelog, error) {
	return service.Changelog{
		ArtifactID: "art1",
		Entries:    []service.ChangelogEntry{},
	}, nil
}

func (f *fakeSearchService) ListSBOMsByDigest(_ context.Context, _ string, limit, offset int32) (service.PagedResult[service.SBOMSummary], error) {
	d := "sha256:abc123"
	return service.PagedResult[service.SBOMSummary]{
		Data:   []service.SBOMSummary{{ID: "sbom1", SpecVersion: "1.5", Version: 1, Digest: &d, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}},
		Total:  1,
		Limit:  limit,
		Offset: offset,
	}, nil
}

func (f *fakeSearchService) DiffSBOMs(_ context.Context, _, _ pgtype.UUID) (service.ChangelogEntry, error) {
	return service.ChangelogEntry{
		From:    service.SBOMRef{ID: "from1"},
		To:      service.SBOMRef{ID: "to1"},
		Summary: service.ChangeSummary{Added: 1},
		Changes: []service.ComponentDiff{{Type: "added", Name: "new-pkg"}},
	}, nil
}

func (f *fakeSearchService) GetArtifactLicenseSummary(_ context.Context, _ pgtype.UUID) ([]service.LicenseCount, error) {
	mit := "MIT"
	return []service.LicenseCount{
		{ID: "lic1", SpdxID: &mit, Name: "MIT License", ComponentCount: 42, Category: "permissive"},
	}, nil
}

func (f *fakeSearchService) GetSBOMDependencies(_ context.Context, _ pgtype.UUID) (service.DependencyGraph, error) {
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

func (f *fakeSearchService) GetComponentVersions(_ context.Context, name, _, _, _ string) ([]service.ComponentVersionEntry, error) {
	return []service.ComponentVersionEntry{
		{ID: "comp1", SbomID: "sbom1", Type: "library", Name: name, SbomCreatedAt: "2025-01-01T00:00:00Z"},
	}, nil
}

func (f *fakeSearchService) ListSBOMComponents(_ context.Context, _ pgtype.UUID) ([]service.ComponentSummary, error) {
	return []service.ComponentSummary{
		{ID: "comp1", SbomID: "sbom1", Name: "test-lib", Type: "library"},
	}, nil
}

func (f *fakeSearchService) ListComponentPurlTypes(_ context.Context) ([]string, error) {
	return []string{"apk", "deb", "golang", "npm", "rpm"}, nil
}

// notFoundSearchService returns ErrNotFound for single-item lookups.
type notFoundSearchService struct{ fakeSearchService }

func (f *notFoundSearchService) GetSBOM(_ context.Context, _ pgtype.UUID, _ bool) (service.SBOMDetail, error) {
	return service.SBOMDetail{}, service.ErrNotFound
}

func (f *notFoundSearchService) GetComponent(_ context.Context, _ pgtype.UUID) (service.ComponentDetail, error) {
	return service.ComponentDetail{}, service.ErrNotFound
}

func (f *notFoundSearchService) GetArtifact(_ context.Context, _ pgtype.UUID) (service.ArtifactDetail, error) {
	return service.ArtifactDetail{}, service.ErrNotFound
}

// pagedBody is a helper for decoding paginated JSON responses.
type pagedBody struct {
	Data       json.RawMessage `json:"data"`
	Pagination struct {
		Total  int64 `json:"total"`
		Limit  int32 `json:"limit"`
		Offset int32 `json:"offset"`
	} `json:"pagination"`
}

func TestListSBOMs(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sbom?limit=10", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)

	var resp pagedBody
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
	is.Equal(resp.Pagination.Total, int64(1))
	is.Equal(resp.Pagination.Limit, int32(10))
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

			r := httptest.NewRequest(http.MethodGet, "/api/v1/sbom/"+tt.id, nil)
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
		{"missing name", "", http.StatusUnprocessableEntity},
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

	var resp pagedBody
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
	is.Equal(resp.Pagination.Total, int64(1))
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

	var resp pagedBody
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
	is.Equal(resp.Pagination.Total, int64(1))
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

func TestListSBOMsByDigest(t *testing.T) {
	tests := []struct {
		name       string
		digest     string
		wantStatus int
	}{
		{"valid digest", "sha256:abc123", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

			r := httptest.NewRequest(http.MethodGet, "/api/v1/sbom/by-digest/"+tt.digest, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)

			var resp pagedBody
			is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
			is.Equal(resp.Pagination.Total, int64(1))
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

			r := httptest.NewRequest(http.MethodGet, "/api/v1/sbom/"+tt.id+"/dependencies", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
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

			r := httptest.NewRequest(http.MethodGet, "/api/v1/diff"+tt.query, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}
