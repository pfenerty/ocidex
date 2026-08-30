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
	"github.com/pfenerty/ocidex/internal/authz"
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

	// mwNamespaceID is the namespace testRegistry hangs from — the anchor
	// RequireCapability resolves to and asks its question of.
	mwNamespaceID = "00000000-0000-0000-0000-0000000000ff"

	// testRegistry is a registry in mwNamespaceID.
	testRegistry = service.Registry{
		ID:          testRegistryID,
		Name:        "test",
		Type:        "generic",
		URL:         "registry.example.com",
		ScanMode:    "webhook",
		NamespaceID: mwNamespaceID,
		OwnerID:     &ownerIDStr,
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

func (f *fakeRegistryService) GetByName(_ context.Context, _ string) (service.Registry, error) {
	return f.registry, f.getErr
}

func (f *fakeRegistryService) Delete(_ context.Context, _ string) error {
	return f.deleteErr
}

func (f *fakeRegistryService) Create(_ context.Context, _ service.CreateRegistryParams) (service.Registry, error) {
	return service.Registry{}, nil
}

func (f *fakeRegistryService) List(_ context.Context, _ service.VisibilityFilter) ([]service.Registry, error) {
	return nil, nil
}

func (f *fakeRegistryService) ListPaged(_ context.Context, _ service.VisibilityFilter, _, _ int32) (service.PagedResult[service.Registry], error) {
	return service.PagedResult[service.Registry]{}, nil
}

func (f *fakeRegistryService) Update(_ context.Context, _ service.UpdateRegistryParams) (service.Registry, error) {
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

func (f *fakeRegistryService) TrustSummary(_ context.Context, _ service.VisibilityFilter) ([]service.RegistryTrustCount, error) {
	return nil, nil
}

type fakeAuthService struct {
	users map[string]service.AuthUser
	// grants maps a user's string ID to that user's namespace roles. It is
	// keyed by user rather than baked into the AuthUser because the real
	// OptionalAuthenticate resolves grants per request rather than reading
	// them off the session row.
	grants map[string]map[string]authz.Role
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

func (f *fakeAuthService) CreateAPIKey(_ context.Context, _ pgtype.UUID, _, _ string) (string, error) {
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

func (f *fakeAuthService) LoadGrants(_ context.Context, userID pgtype.UUID) (map[string]authz.Role, error) {
	if g, ok := f.grants[uuidString(userID)]; ok {
		return g, nil
	}
	return map[string]authz.Role{}, nil
}

// newCapabilityTestRouter builds a router with auth and registry services wired.
// DELETE /registries/{id} is the operation under test: it declares
// authz.CapManageSource, which owner and maintainer hold and security,
// developer and viewer do not.
func newCapabilityTestRouter(regSvc service.RegistryService, authSvc service.AuthService) http.Handler {
	h := api.NewHandler(nil, nil, authSvc, regSvc, nil, nil, nil, nil, nil, nil, &fakePinger{}, nil, nil)
	return api.NewRouter(h, "*", "", "")
}

// deleteRegistryAs issues the delete with the given bearer token, or with no
// credentials at all when token is empty.
func deleteRegistryAs(router http.Handler, token string) int {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/registries/"+testRegistryID, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	router.ServeHTTP(w, r)
	return w.Code
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRequireCapability covers the three answers the middleware owes a caller:
// an anonymous request never reaches the resolve, a member is judged on the
// capability its namespace role grants rather than on who created the row, and
// a global admin passes without any membership at all.
func TestRequireCapability(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		user       service.AuthUser
		role       authz.Role // namespace role, empty means not a member
		wantStatus int
	}{
		{
			name:       "anonymous is unauthenticated",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "admin passes without membership",
			token:      "admin-token",
			user:       service.AuthUser{ID: otherUUID, Role: "admin"},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "maintainer holds manage_source",
			token:      "member-token",
			user:       service.AuthUser{ID: ownerUUID, Role: "member"},
			role:       authz.RoleMaintainer,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "viewer does not hold manage_source",
			token:      "member-token",
			user:       service.AuthUser{ID: ownerUUID, Role: "member"},
			role:       authz.RoleViewer,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "non-member is forbidden",
			token:      "other-token",
			user:       service.AuthUser{ID: otherUUID, Role: "member"},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			authSvc := &fakeAuthService{users: map[string]service.AuthUser{}}
			if tt.token != "" {
				authSvc.users[tt.token] = tt.user
			}
			if tt.role != "" {
				authSvc.grants = map[string]map[string]authz.Role{
					uuidString(tt.user.ID): {mwNamespaceID: tt.role},
				}
			}

			router := newCapabilityTestRouter(&fakeRegistryService{registry: testRegistry}, authSvc)
			is.Equal(deleteRegistryAs(router, tt.token), tt.wantStatus)
		})
	}
}

// TestRequireCapabilityGlobalViewerFloor pins the one rule a namespace owner
// cannot override: an installation-wide viewer given a namespace role still
// gets no capability beyond reading.
func TestRequireCapabilityGlobalViewerFloor(t *testing.T) {
	is := is.New(t)

	authSvc := &fakeAuthService{
		users: map[string]service.AuthUser{
			"viewer-token": {ID: ownerUUID, Role: "viewer"},
		},
		grants: map[string]map[string]authz.Role{
			uuidString(ownerUUID): {mwNamespaceID: authz.RoleOwner},
		},
	}

	router := newCapabilityTestRouter(&fakeRegistryService{registry: testRegistry}, authSvc)
	is.Equal(deleteRegistryAs(router, "viewer-token"), http.StatusForbidden)
}
