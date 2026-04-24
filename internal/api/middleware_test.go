package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/service"
)

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

var (
	// ownerUUID is the pgtype.UUID used as the registry owner in tests.
	ownerUUID = pgtype.UUID{
		Bytes: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Valid: true,
	}
	// ownerIDStr is the string representation of ownerUUID, as produced by
	// the internal uuidToStr helper.
	ownerIDStr = "01020304-0506-0708-090a-0b0c0d0e0f10"

	// otherUUID is a different UUID — used for the non-owner test user.
	otherUUID = pgtype.UUID{
		Bytes: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		Valid: true,
	}

	// testRegistryID is the UUID string used for test registries.
	testRegistryID = "00000000-0000-0000-0000-000000000001"

	// testRegistry is a registry owned by ownerUUID.
	testRegistry = service.Registry{
		ID:       testRegistryID,
		Name:     "test",
		Type:     "generic",
		URL:      "registry.example.com",
		ScanMode: "webhook",
		OwnerID:  &ownerIDStr,
	}
)

// ---------------------------------------------------------------------------
// Fake services
// ---------------------------------------------------------------------------

type fakeRegistryService struct {
	registry  service.Registry
	getErr    error
	deleteErr error
}

func (f *fakeRegistryService) Get(_ context.Context, _ string) (service.Registry, error) {
	return f.registry, f.getErr
}

func (f *fakeRegistryService) Delete(_ context.Context, _ string) error {
	return f.deleteErr
}

func (f *fakeRegistryService) Create(_ context.Context, _, _, _ string, _ bool, _ *string, _, _, _ []string, _ string, _ int, _, _ *string, _ pgtype.UUID, _ string, _ bool) (service.Registry, error) {
	return service.Registry{}, nil
}

func (f *fakeRegistryService) List(_ context.Context, _ service.VisibilityFilter) ([]service.Registry, error) {
	return nil, nil
}

func (f *fakeRegistryService) Update(_ context.Context, _, _, _, _ string, _ bool, _ *string, _ bool, _, _, _ []string, _ string, _ int, _, _ *string, _ string, _ bool) (service.Registry, error) {
	return service.Registry{}, nil
}

func (f *fakeRegistryService) SetEnabled(_ context.Context, _ string, _ bool) (service.Registry, error) {
	return service.Registry{}, nil
}

func (f *fakeRegistryService) ListPollable(_ context.Context) ([]service.Registry, error) {
	return nil, nil
}

func (f *fakeRegistryService) MarkPolled(_ context.Context, _ string) (service.Registry, error) {
	return service.Registry{}, nil
}

type fakeAuthService struct {
	users map[string]service.AuthUser
}

func (f *fakeAuthService) ValidateAPIKey(_ context.Context, token string) (service.AuthUser, error) {
	if u, ok := f.users[token]; ok {
		return u, nil
	}
	return service.AuthUser{}, errors.New("invalid token")
}

func (f *fakeAuthService) BuildAuthURL(_ string) string { return "" }

func (f *fakeAuthService) ExchangeCodeForUser(_ context.Context, _ string) (service.AuthUser, error) {
	return service.AuthUser{}, errors.New("not implemented")
}

func (f *fakeAuthService) CreateSession(_ context.Context, _ pgtype.UUID) (string, error) {
	return "", errors.New("not implemented")
}

func (f *fakeAuthService) ValidateSession(_ context.Context, _ string) (service.AuthUser, error) {
	return service.AuthUser{}, errors.New("not implemented")
}

func (f *fakeAuthService) DeleteSession(_ context.Context, _ string) error {
	return errors.New("not implemented")
}

func (f *fakeAuthService) CreateAPIKey(_ context.Context, _ pgtype.UUID, _ string) (string, error) {
	return "", errors.New("not implemented")
}

func (f *fakeAuthService) ListAPIKeys(_ context.Context, _ pgtype.UUID) ([]service.APIKeyMeta, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeAuthService) DeleteAPIKey(_ context.Context, _ pgtype.UUID, _ pgtype.UUID) error {
	return errors.New("not implemented")
}

func (f *fakeAuthService) GetUser(_ context.Context, _ pgtype.UUID) (service.AuthUser, error) {
	return service.AuthUser{}, errors.New("not implemented")
}

func (f *fakeAuthService) ListUsers(_ context.Context) ([]service.AuthUser, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeAuthService) UpdateUserRole(_ context.Context, _ pgtype.UUID, _ string) (service.AuthUser, error) {
	return service.AuthUser{}, errors.New("not implemented")
}

func (f *fakeAuthService) CleanExpiredSessions(_ context.Context) error {
	return nil
}

// newRegistryOwnerTestRouter builds a router with auth and registry services wired.
func newRegistryOwnerTestRouter(regSvc service.RegistryService, authSvc service.AuthService) http.Handler {
	h := api.NewHandler(nil, nil, authSvc, regSvc, &fakePinger{}, nil, nil)
	return api.NewRouter(h, "*", "", "")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRequireRegistryOwner_AdminAllowed(t *testing.T) {
	is := is.New(t)

	authSvc := &fakeAuthService{
		users: map[string]service.AuthUser{
			"admin-token": {ID: otherUUID, Role: "admin"},
		},
	}
	regSvc := &fakeRegistryService{registry: testRegistry}
	router := newRegistryOwnerTestRouter(regSvc, authSvc)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/registries/"+testRegistryID, nil)
	r.Header.Set("Authorization", "Bearer admin-token")
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusNoContent)
}

func TestRequireRegistryOwner_OwnerAllowed(t *testing.T) {
	is := is.New(t)

	authSvc := &fakeAuthService{
		users: map[string]service.AuthUser{
			"owner-token": {ID: ownerUUID, Role: "member"},
		},
	}
	regSvc := &fakeRegistryService{registry: testRegistry}
	router := newRegistryOwnerTestRouter(regSvc, authSvc)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/registries/"+testRegistryID, nil)
	r.Header.Set("Authorization", "Bearer owner-token")
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusNoContent)
}

func TestRequireRegistryOwner_NonOwnerForbidden(t *testing.T) {
	is := is.New(t)

	authSvc := &fakeAuthService{
		users: map[string]service.AuthUser{
			"other-token": {ID: otherUUID, Role: "member"},
		},
	}
	regSvc := &fakeRegistryService{registry: testRegistry}
	router := newRegistryOwnerTestRouter(regSvc, authSvc)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/registries/"+testRegistryID, nil)
	r.Header.Set("Authorization", "Bearer other-token")
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusForbidden)
}

func TestRequireRegistryOwner_UnauthForbidden(t *testing.T) {
	is := is.New(t)

	authSvc := &fakeAuthService{users: map[string]service.AuthUser{}}
	regSvc := &fakeRegistryService{registry: testRegistry}
	router := newRegistryOwnerTestRouter(regSvc, authSvc)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/registries/"+testRegistryID, nil)
	// No Authorization header
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusUnauthorized)
}
