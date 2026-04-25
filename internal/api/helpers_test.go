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

func (f *fakeSBOMService) ListDigestsByRegistry(_ context.Context, _ string) (map[string]bool, error) {
	return nil, nil
}

func (f *fakeSBOMService) GetSBOMRegistryID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
	return pgtype.UUID{}, nil
}

func (f *fakeSBOMService) GetArtifactOwnerID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
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

func (f *failSBOMService) ListDigestsByRegistry(_ context.Context, _ string) (map[string]bool, error) {
	return nil, errors.New("database unavailable")
}

func (f *failSBOMService) GetSBOMRegistryID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
	return pgtype.UUID{}, errors.New("database unavailable")
}

func (f *failSBOMService) GetArtifactOwnerID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
	return pgtype.UUID{}, errors.New("database unavailable")
}

// ---------------------------------------------------------------------------
// Router / handler builders
// ---------------------------------------------------------------------------

// newTestRouter builds a full huma router backed by the given services and a
// healthy fakePinger. Auth middleware is disabled (nil authSvc).
func newTestRouter(sbomSvc service.SBOMService, searchSvc service.SearchService) http.Handler {
	h := api.NewHandler(sbomSvc, searchSvc, nil, nil, &fakePinger{}, nil, nil)
	return api.NewRouter(h, "*", "", "")
}

// newTestRouterWithAuth builds a router with an auth service wired (so
// OptionalAuthenticate and huma auth-gate middlewares function properly).
func newTestRouterWithAuth(sbomSvc service.SBOMService, searchSvc service.SearchService, authSvc service.AuthService) http.Handler {
	h := api.NewHandler(sbomSvc, searchSvc, authSvc, nil, &fakePinger{}, nil, nil)
	return api.NewRouter(h, "*", "", "")
}

// newTestHandlerWithPinger creates a Handler with a custom DBPinger (e.g. for
// testing readiness failures). Auth middleware is disabled (nil authSvc).
func newTestHandlerWithPinger(sbomSvc service.SBOMService, searchSvc service.SearchService, pinger api.DBPinger) *api.Handler {
	return api.NewHandler(sbomSvc, searchSvc, nil, nil, pinger, nil, nil)
}

// newTestRouterFromHandler builds a full huma router from an existing Handler.
func newTestRouterFromHandler(h *api.Handler) http.Handler {
	return api.NewRouter(h, "*", "", "")
}
