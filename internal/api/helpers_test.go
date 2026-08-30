package api_test

import (
	"context"
	"errors"
	"net/http"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/service"
)

// ---------------------------------------------------------------------------
// Fake SBOMService implementations
// ---------------------------------------------------------------------------

// fakeSBOMService is a stub that always succeeds.
type fakeSBOMService struct{}

func (f *fakeSBOMService) Ingest(_ context.Context, _ *cdx.BOM, _ []byte, _ service.IngestParams) (pgtype.UUID, error) {
	return pgtype.UUID{
		Bytes: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Valid: true,
	}, nil
}

func (f *fakeSBOMService) DeleteSBOM(_ context.Context, _ pgtype.UUID) error {
	return nil
}

func (f *fakeSBOMService) DeleteArtifact(_ context.Context, _ pgtype.UUID) error {
	return nil
}

func (f *fakeSBOMService) ListDigestsBySource(_ context.Context, _ string) (map[string]bool, error) {
	return nil, nil
}

func (f *fakeSBOMService) GetSBOMNamespaceID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
	return pgtype.UUID{}, nil
}

func (f *fakeSBOMService) GetArtifactNamespaceID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
	return pgtype.UUID{}, nil
}

// failSBOMService is a stub that always returns an error.
type failSBOMService struct{}

func (f *failSBOMService) Ingest(_ context.Context, _ *cdx.BOM, _ []byte, _ service.IngestParams) (pgtype.UUID, error) {
	return pgtype.UUID{}, errors.New("database unavailable")
}

func (f *failSBOMService) DeleteSBOM(_ context.Context, _ pgtype.UUID) error {
	return errors.New("database unavailable")
}

func (f *failSBOMService) DeleteArtifact(_ context.Context, _ pgtype.UUID) error {
	return errors.New("database unavailable")
}

func (f *failSBOMService) ListDigestsBySource(_ context.Context, _ string) (map[string]bool, error) {
	return nil, errors.New("database unavailable")
}

func (f *failSBOMService) GetSBOMNamespaceID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
	return pgtype.UUID{}, errors.New("database unavailable")
}

func (f *failSBOMService) GetArtifactNamespaceID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
	return pgtype.UUID{}, errors.New("database unavailable")
}

// ---------------------------------------------------------------------------
// Fake namespace / source services
// ---------------------------------------------------------------------------

const (
	// testSourceID is the source every ingest test posts to, and
	// testNamespaceID the namespace that owns it — owned in turn by ownerUUID,
	// the user memberAuthSvc authenticates.
	testSourceID    = "0a0b0c0d-0e0f-1011-1213-141516171819"
	testNamespaceID = "1a1b1c1d-1e1f-2021-2223-242526272829"

	// testClusterID is the cluster fakeClusterService resolves every id to; it
	// hangs from testNamespaceID so cluster ownership resolves the same way.
	testClusterID = "2a2b2c2d-2e2f-3031-3233-343536373839"

	// ingestPath is the ingest route bound to that source. Ingest derives the
	// owning namespace from the source, so posting without one is a 400
	// (ADR-039) — every ingest test needs a source in the URL.
	ingestPath = "/api/v1/sboms?source=" + testSourceID
)

// fakeNamespaceService resolves any id or name to a single namespace owned by
// ownerUUID, so ownership checks pass for the member token and fail for anyone
// else.
type fakeNamespaceService struct{}

func (f *fakeNamespaceService) Create(_ context.Context, _ service.CreateNamespaceParams) (service.Namespace, error) {
	return f.ns(), nil
}

func (f *fakeNamespaceService) Get(_ context.Context, _ string) (service.Namespace, error) {
	return f.ns(), nil
}

func (f *fakeNamespaceService) GetByName(_ context.Context, _ string) (service.Namespace, error) {
	return f.ns(), nil
}

func (f *fakeNamespaceService) List(_ context.Context, _ service.VisibilityFilter) ([]service.Namespace, error) {
	return []service.Namespace{f.ns()}, nil
}

func (f *fakeNamespaceService) Update(_ context.Context, _ service.UpdateNamespaceParams) (service.Namespace, error) {
	return f.ns(), nil
}

func (f *fakeNamespaceService) Delete(_ context.Context, _ string) error { return nil }

func (f *fakeNamespaceService) ns() service.Namespace {
	owner := ownerIDStr
	return service.Namespace{
		ID:         testNamespaceID,
		Name:       "test-ns",
		OwnerID:    &owner,
		Visibility: "private",
	}
}

// fakeSourceService resolves any reference to a single upload source inside
// testNamespaceID.
type fakeSourceService struct{}

func (f *fakeSourceService) Create(_ context.Context, _ service.CreateSourceParams) (service.Source, error) {
	return f.src(), nil
}

func (f *fakeSourceService) Get(_ context.Context, _ string) (service.Source, error) {
	return f.src(), nil
}

func (f *fakeSourceService) GetByName(_ context.Context, _, _ string) (service.Source, error) {
	return f.src(), nil
}

func (f *fakeSourceService) ListByNamespace(_ context.Context, _ string) ([]service.Source, error) {
	return []service.Source{f.src()}, nil
}

func (f *fakeSourceService) List(_ context.Context, _ service.VisibilityFilter) ([]service.Source, error) {
	return []service.Source{f.src()}, nil
}

func (f *fakeSourceService) Update(_ context.Context, _ service.UpdateSourceParams) (service.Source, error) {
	return f.src(), nil
}

func (f *fakeSourceService) Delete(_ context.Context, _ string) error { return nil }

func (f *fakeSourceService) src() service.Source {
	return service.Source{
		ID:          testSourceID,
		NamespaceID: testNamespaceID,
		Kind:        "upload",
		Name:        "ci",
	}
}

// fakeClusterService resolves any reference to a single cluster inside
// testNamespaceID, so the ownership check on a cluster route lands on
// fakeNamespaceService rather than on a nil pointer.
type fakeClusterService struct{}

func (f *fakeClusterService) Create(_ context.Context, _ service.CreateClusterParams) (service.Cluster, error) {
	return f.cluster(), nil
}

func (f *fakeClusterService) Get(_ context.Context, _ string) (service.Cluster, error) {
	return f.cluster(), nil
}

func (f *fakeClusterService) GetByName(_ context.Context, _, _ string) (service.Cluster, error) {
	return f.cluster(), nil
}

func (f *fakeClusterService) ListByNamespace(_ context.Context, _ string) ([]service.Cluster, error) {
	return []service.Cluster{f.cluster()}, nil
}

func (f *fakeClusterService) List(_ context.Context, _ service.VisibilityFilter) ([]service.Cluster, error) {
	return []service.Cluster{f.cluster()}, nil
}

func (f *fakeClusterService) Update(_ context.Context, _ service.UpdateClusterParams) (service.Cluster, error) {
	return f.cluster(), nil
}

func (f *fakeClusterService) Delete(_ context.Context, _ string) error { return nil }

func (f *fakeClusterService) ReplaceInventory(_ context.Context, _ string, _ []service.ReportedWorkload) (int, error) {
	return 0, nil
}

func (f *fakeClusterService) ListWorkloads(_ context.Context, _ string, _ service.WorkloadParams, _ service.VisibilityFilter) (service.PagedResult[service.ClusterWorkload], error) {
	return service.PagedResult[service.ClusterWorkload]{}, nil
}

func (f *fakeClusterService) ListImages(_ context.Context, _ string, _ service.ImageParams, _ service.VisibilityFilter) (service.PagedResult[service.ClusterImage], error) {
	return service.PagedResult[service.ClusterImage]{}, nil
}

func (f *fakeClusterService) NamespaceFacets(_ context.Context, _ string, _ service.VisibilityFilter) ([]service.NamespaceFacet, error) {
	return nil, nil
}

func (f *fakeClusterService) Coverage(_ context.Context, _ string, _ service.VisibilityFilter) (service.WorkloadCoverage, error) {
	return service.WorkloadCoverage{}, nil
}

func (f *fakeClusterService) RunningVulns(_ context.Context, _ string, _ service.RunningVulnParams, _ service.VisibilityFilter) (service.PagedResult[service.RunningVuln], error) {
	return service.PagedResult[service.RunningVuln]{}, nil
}

func (f *fakeClusterService) WorkloadsForVulnerability(_ context.Context, _, _ string, _ int32, _ service.VisibilityFilter) ([]service.RunningWorkload, error) {
	return nil, nil
}

func (f *fakeClusterService) UnknownImages(_ context.Context, _ string, _, _ int32, _ service.VisibilityFilter) (service.UnknownImagesPage, error) {
	return service.UnknownImagesPage{}, nil
}

func (f *fakeClusterService) IngestUnknown(_ context.Context, _ string, _ service.RunningImageSubmitter, _ service.IngestUnknownParams, _ service.VisibilityFilter) (service.IngestResult, error) {
	return service.IngestResult{}, nil
}

func (f *fakeClusterService) cluster() service.Cluster {
	return service.Cluster{
		ID:          testClusterID,
		NamespaceID: testNamespaceID,
		Name:        "prod",
	}
}

// ---------------------------------------------------------------------------
// Router / handler builders
// ---------------------------------------------------------------------------

// newTestRouter builds a full huma router backed by the given services and a
// healthy fakePinger. Auth middleware is disabled (nil authSvc).
func newTestRouter(sbomSvc service.SBOMService, searchSvc service.SearchService) http.Handler {
	h := api.NewHandler(sbomSvc, searchSvc, nil, nil, nil, nil, nil, nil, nil, nil, &fakePinger{}, nil, nil)
	return api.NewRouter(h, "*", "", "")
}

// newTestRouterWithAuth builds a router with an auth service wired so that
// OptionalAuthenticate and huma auth-gate middlewares function properly.
func newTestRouterWithAuth(sbomSvc service.SBOMService, searchSvc service.SearchService, authSvc service.AuthService) http.Handler {
	h := api.NewHandler(sbomSvc, searchSvc, authSvc, nil,
		&fakeNamespaceService{}, &fakeSourceService{}, nil, nil, nil, nil, &fakePinger{}, nil, nil)
	return api.NewRouter(h, "*", "", "")
}

// newTestHandlerWithPinger creates a Handler with a custom DBPinger (e.g. for
// testing readiness failures). Auth middleware is disabled (nil authSvc).
func newTestHandlerWithPinger(sbomSvc service.SBOMService, searchSvc service.SearchService, pinger api.DBPinger) *api.Handler {
	return api.NewHandler(sbomSvc, searchSvc, nil, nil, nil, nil, nil, nil, nil, nil, pinger, nil, nil)
}

// newTestRouterFromHandler builds a full huma router from an existing Handler.
func newTestRouterFromHandler(h *api.Handler) http.Handler {
	return api.NewRouter(h, "*", "", "")
}
