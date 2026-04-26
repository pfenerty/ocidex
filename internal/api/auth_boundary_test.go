package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/service"
)

// ---------------------------------------------------------------------------
// Principal tokens and UUIDs
// ---------------------------------------------------------------------------

const (
	tokenAdminRW  = "admin-rw"
	tokenAdminRO  = "admin-ro"
	tokenMemberRW = "member-rw"
	tokenMemberRO = "member-ro"
	tokenViewerRW = "viewer-rw"

	// validKeyUUID is a well-formed UUID used as the key ID in DELETE path tests.
	validKeyUUID = "00000000-0000-0000-0000-000000000099"
	// validUserUUID is a well-formed UUID used as the target user ID in PATCH path tests.
	validUserUUID = "00000000-0000-0000-0000-000000000088"
)

var (
	boundaryAdminUUID  = pgtype.UUID{Bytes: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}, Valid: true}
	boundaryMemberUUID = pgtype.UUID{Bytes: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11}, Valid: true}
	boundaryViewerUUID = pgtype.UUID{Bytes: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12}, Valid: true}
)

// ---------------------------------------------------------------------------
// configFakeAuthService — extends fakeAuthService with working operation stubs
// ---------------------------------------------------------------------------

type configFakeAuthService struct {
	fakeAuthService
	listUsersOut  []service.AuthUser
	updateRoleOut service.AuthUser
	createKeyOut  string
	listKeysOut   []service.APIKeyMeta
}

func (f *configFakeAuthService) ListUsers(_ context.Context) ([]service.AuthUser, error) {
	return f.listUsersOut, nil
}

func (f *configFakeAuthService) UpdateUserRole(_ context.Context, _ pgtype.UUID, _ string) (service.AuthUser, error) {
	return f.updateRoleOut, nil
}

func (f *configFakeAuthService) CreateAPIKey(_ context.Context, _ pgtype.UUID, _, _ string) (string, error) {
	return f.createKeyOut, nil
}

func (f *configFakeAuthService) ListAPIKeys(_ context.Context, _ pgtype.UUID) ([]service.APIKeyMeta, error) {
	return f.listKeysOut, nil
}

func (f *configFakeAuthService) DeleteAPIKey(_ context.Context, _ pgtype.UUID, _ pgtype.UUID) error {
	return nil
}

// newBoundaryAuthSvc builds a configFakeAuthService with all test principals registered.
func newBoundaryAuthSvc() *configFakeAuthService {
	return &configFakeAuthService{
		fakeAuthService: fakeAuthService{
			users: map[string]service.AuthUser{
				tokenAdminRW:  {ID: boundaryAdminUUID, GitHubUsername: "admin", Role: "admin", APIKeyScope: ""},
				tokenAdminRO:  {ID: boundaryAdminUUID, GitHubUsername: "admin", Role: "admin", APIKeyScope: "read"},
				tokenMemberRW: {ID: boundaryMemberUUID, GitHubUsername: "member", Role: "member", APIKeyScope: ""},
				tokenMemberRO: {ID: boundaryMemberUUID, GitHubUsername: "member", Role: "member", APIKeyScope: "read"},
				tokenViewerRW: {ID: boundaryViewerUUID, GitHubUsername: "viewer", Role: "viewer", APIKeyScope: ""},
			},
		},
		listUsersOut:  []service.AuthUser{},
		listKeysOut:   []service.APIKeyMeta{},
		createKeyOut:  "ocidex_test_key",
		updateRoleOut: service.AuthUser{ID: boundaryAdminUUID, Role: "viewer"},
	}
}

// newAuthBoundaryRouter builds a router with auth wired and a zero-value Config.
// Config must be non-nil because GetSystemStatus accesses cfg fields directly.
func newAuthBoundaryRouter(authSvc service.AuthService) http.Handler {
	h := api.NewHandler(nil, nil, authSvc, nil, nil, &fakePinger{}, nil, &config.Config{})
	return api.NewRouter(h, "*", "", "")
}

// ---------------------------------------------------------------------------
// Request helper
// ---------------------------------------------------------------------------

func doAuthRequest(router http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	var bodyBytes []byte
	if body != "" {
		bodyBytes = []byte(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

// ---------------------------------------------------------------------------
// TestRoleEnforcement: representative endpoints × 4 principals
// ---------------------------------------------------------------------------

func TestRoleEnforcement(t *testing.T) {
	router := newAuthBoundaryRouter(newBoundaryAuthSvc())

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		unauth int
		viewer int
		member int
		admin  int
	}{
		{"list-users", http.MethodGet, "/api/v1/users", "", 401, 403, 403, 200},
		{"system-status", http.MethodGet, "/api/v1/admin/status", "", 401, 403, 403, 200},
		{"get-me", http.MethodGet, "/api/v1/users/me", "", 401, 200, 200, 200},
		{"list-keys", http.MethodGet, "/api/v1/auth/keys", "", 401, 403, 200, 200},
		{"create-key", http.MethodPost, "/api/v1/auth/keys", `{"name":"k"}`, 401, 403, 201, 201},
		{"delete-key", http.MethodDelete, "/api/v1/auth/keys/" + validKeyUUID, "", 401, 403, 204, 204},
		{"update-role", http.MethodPatch, "/api/v1/users/" + validUserUUID + "/role", `{"role":"viewer"}`, 401, 403, 403, 200},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			principals := []struct {
				token    string
				expected int
			}{
				{"", tc.unauth},
				{tokenViewerRW, tc.viewer},
				{tokenMemberRW, tc.member},
				{tokenAdminRW, tc.admin},
			}
			for _, p := range principals {
				is := is.New(t)
				w := doAuthRequest(router, tc.method, tc.path, tc.body, p.token)
				is.Equal(w.Code, p.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestWriteScopeEnforcement: read-only API keys rejected on write operations
// ---------------------------------------------------------------------------

func TestWriteScopeEnforcement(t *testing.T) {
	router := newAuthBoundaryRouter(newBoundaryAuthSvc())

	cases := []struct {
		name   string
		token  string
		method string
		path   string
		body   string
	}{
		{"member-ro-create-key", tokenMemberRO, http.MethodPost, "/api/v1/auth/keys", `{"name":"k"}`},
		{"member-ro-delete-key", tokenMemberRO, http.MethodDelete, "/api/v1/auth/keys/" + validKeyUUID, ""},
		{"admin-ro-update-role", tokenAdminRO, http.MethodPatch, "/api/v1/users/" + validUserUUID + "/role", `{"role":"viewer"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			w := doAuthRequest(router, tc.method, tc.path, tc.body, tc.token)
			is.Equal(w.Code, http.StatusForbidden)
		})
	}
}

// ---------------------------------------------------------------------------
// TestAuthBoundary_InvalidInput: validation error paths
// ---------------------------------------------------------------------------

func TestAuthBoundary_InvalidInput(t *testing.T) {
	is := is.New(t)
	router := newAuthBoundaryRouter(newBoundaryAuthSvc())

	// Non-UUID key ID: huma validates the format:"uuid" path param and returns 422.
	w := doAuthRequest(router, http.MethodDelete, "/api/v1/auth/keys/not-a-uuid", "", tokenAdminRW)
	is.Equal(w.Code, http.StatusUnprocessableEntity)
}
