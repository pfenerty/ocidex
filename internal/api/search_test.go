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

type fakeSearchService struct {
	// discovery overrides the payload GetDiscovery returns; nil means a warm
	// snapshot with empty sections.
	discovery *service.Discovery
}

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

func (f *fakeSearchService) GetComponentVersions(_ context.Context, filter service.ComponentVersionFilter) (service.ComponentVersionsPage, error) {
	return service.ComponentVersionsPage{
		PagedResult: service.PagedResult[service.ComponentVersionEntry]{
			Data: []service.ComponentVersionEntry{
				{ID: "comp1", SbomID: "sbom1", Type: "library", Name: filter.Name, SbomCreatedAt: "2025-01-01T00:00:00Z"},
			},
			Total:  1,
			Limit:  filter.Limit,
			Offset: filter.Offset,
		},
		VersionCount:  1,
		ArtifactCount: 1,
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

func (f *fakeSearchService) GetDiscovery(_ context.Context) (*service.Discovery, error) {
	if f.discovery != nil {
		return f.discovery, nil
	}
	return &service.Discovery{GeneratedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}

func (f *fakeSearchService) WarmDiscovery(_ context.Context) (*service.Discovery, error) {
	return &service.Discovery{}, nil
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

func (f *fakeSearchService) GetVulnerabilityDetail(_ context.Context, _ string, limit, offset int32, _ service.VisibilityFilter) (service.VulnerabilityDetailResult, error) {
	return service.VulnerabilityDetailResult{
		Detail:         &service.VulnDetail{ID: "CVE-2021-0001", Severity: "HIGH", Aliases: []string{}},
		Artifacts:      service.PagedResult[service.AffectedArtifact]{Total: 9, Limit: limit, Offset: offset},
		Components:     service.PagedResult[service.AffectedComponent]{},
		NamespaceCount: 4,
	}, nil
}

func (f *fakeSearchService) GetComponentVulns(_ context.Context, _ pgtype.UUID, _ service.VisibilityFilter) ([]service.ComponentVulnEntry, error) {
	return []service.ComponentVulnEntry{}, nil
}

func (f *fakeSearchService) ListSBOMVulns(_ context.Context, _ pgtype.UUID, _ service.SBOMVulnParams, _ service.VisibilityFilter) (service.PagedResult[service.SBOMVulnEntry], error) {
	return service.PagedResult[service.SBOMVulnEntry]{
		Data: []service.SBOMVulnEntry{{
			ID:                   "GHSA-xxxx",
			CanonicalID:          "CVE-2024-0001",
			Severity:             "HIGH",
			AffectedPackageCount: 2,
			AffectedPackages: []service.SBOMVulnPackage{
				{Purl: "pkg:deb/debian/zlib1g@1.0", Name: "zlib1g"},
				{Purl: "pkg:deb/debian/libc6@2.0", Name: "libc6", MatchedViaSource: true},
			},
		}},
		Total:  1,
		Limit:  20,
		Offset: 0,
	}, nil
}

func (f *fakeSearchService) ListArtifactVulns(_ context.Context, _ pgtype.UUID, _ service.ArtifactVulnParams, _ service.VisibilityFilter) (service.PagedResult[service.ArtifactVulnEntry], error) {
	return service.PagedResult[service.ArtifactVulnEntry]{
		Data: []service.ArtifactVulnEntry{{
			ID:                   "GHSA-yyyy",
			CanonicalID:          "CVE-2024-0002",
			Severity:             "CRITICAL",
			AffectedPackageCount: 1,
			AffectedVersionCount: 2,
			AffectedVersions: []service.ArtifactVulnVersion{
				{Version: "1.0.0", SbomID: "11111111-1111-1111-1111-111111111111", AffectedPackageCount: 1, PackageNames: []string{"zlib1g"}},
				{Version: "1.1.0", SbomID: "22222222-2222-2222-2222-222222222222", AffectedPackageCount: 1, PackageNames: []string{"zlib1g"}},
			},
		}},
		Total:  1,
		Limit:  20,
		Offset: 0,
	}, nil
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

func (f *notFoundSearchService) ListSBOMVulns(_ context.Context, _ pgtype.UUID, _ service.SBOMVulnParams, _ service.VisibilityFilter) (service.PagedResult[service.SBOMVulnEntry], error) {
	return service.PagedResult[service.SBOMVulnEntry]{}, service.ErrNotFound
}

func (f *notFoundSearchService) ListArtifactVulns(_ context.Context, _ pgtype.UUID, _ service.ArtifactVulnParams, _ service.VisibilityFilter) (service.PagedResult[service.ArtifactVulnEntry], error) {
	return service.PagedResult[service.ArtifactVulnEntry]{}, service.ErrNotFound
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

type capturingVersionsService struct {
	fakeSearchService
	filter service.ComponentVersionFilter
}

func (f *capturingVersionsService) GetComponentVersions(_ context.Context, filter service.ComponentVersionFilter) (service.ComponentVersionsPage, error) {
	f.filter = filter
	return service.ComponentVersionsPage{
		PagedResult: service.PagedResult[service.ComponentVersionEntry]{
			Data:   []service.ComponentVersionEntry{{ID: "comp1", Name: filter.Name}},
			Total:  4210,
			Limit:  filter.Limit,
			Offset: filter.Offset,
		},
		VersionCount:  37,
		ArtifactCount: 12,
	}, nil
}

// The endpoint was unpaginated and returned a component's whole version
// history, which timed out at 30s for the very names /components links most
// (ocidex-ag4q.7). Paginating it is only useful if the window reaches the
// service and the total comes back out — a page with no total leaves the UI
// unable to say there is a second one.
func TestGetComponentVersionsPaginates(t *testing.T) {
	is := is.New(t)
	search := &capturingVersionsService{}
	router := newTestRouter(&fakeSBOMService{}, search)

	r := httptest.NewRequest(http.MethodGet,
		"/api/v1/components/versions?name="+url.QueryEscape("golang.org/x/crypto")+"&limit=20&offset=40", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)
	is.Equal(search.filter.Name, "golang.org/x/crypto")
	is.Equal(search.filter.Limit, int32(20))
	is.Equal(search.filter.Offset, int32(40))

	var body struct {
		Versions   []service.ComponentVersionEntry `json:"versions"`
		Pagination struct {
			Total  int64 `json:"total"`
			Limit  int32 `json:"limit"`
			Offset int32 `json:"offset"`
		} `json:"pagination"`
	}
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &body))
	is.Equal(len(body.Versions), 1)
	is.Equal(body.Pagination.Total, int64(4210))
	is.Equal(body.Pagination.Limit, int32(20))
	is.Equal(body.Pagination.Offset, int32(40))
}

// The summary band asks two questions the page cannot answer — how many
// versions exist, and how many artifacts carry them — so both have to reach the
// body as their own fields. Pagination.Total is a third figure (SBOM
// occurrences) and must not be conflated with either (ocidex-ag4q.35).
func TestGetComponentVersionsReportsCorpusWideCounts(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &capturingVersionsService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/components/versions?name=zlib", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	is.Equal(w.Code, http.StatusOK)

	var body struct {
		VersionCount  int64 `json:"versionCount"`
		ArtifactCount int64 `json:"artifactCount"`
		Pagination    struct {
			Total int64 `json:"total"`
		} `json:"pagination"`
	}
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &body))
	is.Equal(body.VersionCount, int64(37))
	is.Equal(body.ArtifactCount, int64(12))
	is.Equal(body.Pagination.Total, int64(4210))
}

// The advisory page reports two different scopes: how much of the catalog is
// affected, and how many namespaces it reaches. Deriving the second from a page
// of artifacts is not possible, so it has to survive the handler as its own
// field rather than collapsing into pagination.total.
func TestGetVulnerabilityReportsNamespaceScope(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/vulns/CVE-2021-0001", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	is.Equal(w.Code, http.StatusOK)

	var body struct {
		NamespaceCount int64 `json:"namespaceCount"`
		Pagination     struct {
			Total int64 `json:"total"`
		} `json:"pagination"`
	}
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &body))
	is.Equal(body.NamespaceCount, int64(4))
	is.Equal(body.Pagination.Total, int64(9))
}

// An unbounded caller must not be able to ask for the whole history again.
func TestGetComponentVersionsDefaultsAndCapsTheWindow(t *testing.T) {
	is := is.New(t)
	search := &capturingVersionsService{}
	router := newTestRouter(&fakeSBOMService{}, search)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/components/versions?name=zlib", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	is.Equal(w.Code, http.StatusOK)
	is.Equal(search.filter.Limit, int32(20))
	is.Equal(search.filter.Offset, int32(0))

	r = httptest.NewRequest(http.MethodGet, "/api/v1/components/versions?name=zlib&limit=5000", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, r)
	is.Equal(w.Code, http.StatusUnprocessableEntity)
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

// TestGetDiscoveryCacheControl pins the two cache dispositions apart. Serving a
// warming payload as cacheable is the failure that matters: an edge would pin an
// empty landing page in place for the whole max-age after the real snapshot was
// already available.
func TestGetDiscoveryCacheControl(t *testing.T) {
	tests := []struct {
		name      string
		discovery *service.Discovery
		wantCache string
	}{
		{"warm", nil, "public, max-age=60, stale-while-revalidate=300"},
		{"warming", &service.Discovery{Warming: true}, "no-store"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{discovery: tt.discovery})

			r := httptest.NewRequest(http.MethodGet, "/api/v1/discover", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, http.StatusOK)
			is.Equal(w.Header().Get("Cache-Control"), tt.wantCache)

			var body struct {
				TopArtifacts       []struct{ Name string } `json:"top_artifacts"`
				RecentArtifacts    []struct{ Name string } `json:"recent_artifacts"`
				TopVulnerabilities []struct{ ID string }   `json:"top_vulnerabilities"`
				LicenseSpread      []struct{ Name string } `json:"license_spread"`
				GeneratedAt        string                  `json:"generated_at"`
				Warming            bool                    `json:"warming"`
			}
			is.NoErr(json.Unmarshal(w.Body.Bytes(), &body))
			is.Equal(body.Warming, tt.discovery != nil)
			// generated_at is meaningful only for a real snapshot; a warming
			// response must not claim one.
			is.Equal(body.GeneratedAt == "", body.Warming)
		})
	}
}

// TestGetDiscoveryIdenticalForEveryCaller is the cacheability precondition: the
// endpoint takes no viewer input, so an authenticated request must get exactly
// the bytes an anonymous one gets. If personalisation ever leaks in here, the
// edge cache would start serving one user's view to everyone.
func TestGetDiscoveryIdenticalForEveryCaller(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	get := func(auth string) string {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/discover", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		is.Equal(w.Code, http.StatusOK)
		return w.Body.String()
	}

	is.Equal(get(""), get("Bearer some-api-key"))
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
