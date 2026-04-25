package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/service"
)

const testSessionSecret = "test-session-secret-padded-32b!" // 32 bytes

const patchRegistryBody = `{"name":"updated","type":"generic","url":"registry.example.com","insecure":false,"enabled":true,"repositories":[],"repository_patterns":[],"tag_patterns":[]}`

func registryBody(name string) string {
	return `{"name":"` + name + `","type":"generic","url":"registry.example.com","insecure":false,"visibility":"public","scan_mode":"poll","repositories":[],"repository_patterns":[],"tag_patterns":[]}`
}

func setupServerWithAuth(t *testing.T, pool *pgxpool.Pool) (*httptest.Server, service.AuthService) {
	t.Helper()
	cfg := &config.Config{SessionSecret: testSessionSecret}
	authSvc := service.NewAuthService(pool, cfg)
	sbomSvc := service.NewSBOMService(pool, nil, nil)
	searchSvc := service.NewSearchService(pool)
	registrySvc := service.NewRegistryService(pool)
	handler := api.NewHandler(sbomSvc, searchSvc, authSvc, registrySvc, pool, nil, cfg)
	router := api.NewRouter(handler, "*", "", "")
	return httptest.NewServer(router), authSvc
}

func seedUser(t *testing.T, pool *pgxpool.Pool, githubID int64, username, role string) pgtype.UUID {
	t.Helper()
	var id pgtype.UUID
	row := pool.QueryRow(t.Context(),
		"INSERT INTO ocidex_user (github_id, github_username, role) VALUES ($1, $2, $3) RETURNING id",
		githubID, username, role)
	if err := row.Scan(&id); err != nil {
		t.Fatalf("seeding user %s: %v", username, err)
	}
	return id
}

// doWithAuth performs an HTTP request with an optional Bearer token.
func doWithAuth(t *testing.T, method, url, body, apiKey string) (*http.Response, error) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, url, r)
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return http.DefaultClient.Do(req)
}

func TestAuthBoundaries(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	ctx := t.Context()

	// Seed users directly via SQL (no service-level user creation method).
	adminID := seedUser(t, pool, 1001, "test-admin", "admin")
	memberID := seedUser(t, pool, 1002, "test-member", "member")
	viewerID := seedUser(t, pool, 1003, "test-viewer", "viewer")

	adminKey, err := authSvc.CreateAPIKey(ctx, adminID, "test")
	is.NoErr(err)
	memberKey, err := authSvc.CreateAPIKey(ctx, memberID, "test")
	is.NoErr(err)
	viewerKey, err := authSvc.CreateAPIKey(ctx, viewerID, "test")
	is.NoErr(err)

	// Create a registry owned by member; used for owner-middleware cases.
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/registries", registryBody("owner-reg"), memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var regResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&regResp))
	resp.Body.Close()
	memberRegID := regResp["id"].(string)

	type authCase struct {
		name       string
		method     string
		path       string
		body       string
		anonWant   int
		viewerWant int
		memberWant int
		adminWant  int
	}

	cases := []authCase{
		// Public read — no auth required.
		{"list sboms", http.MethodGet, "/api/v1/sboms", "", 200, 200, 200, 200},
		{"list artifacts", http.MethodGet, "/api/v1/artifacts", "", 200, 200, 200, 200},
		{"search components", http.MethodGet, "/api/v1/components?name=bash", "", 200, 200, 200, 200},
		{"stats", http.MethodGet, "/api/v1/stats", "", 200, 200, 200, 200},
		// SBOM ingest — no auth protection (intentional; any caller may push SBOMs).
		{"ingest sbom", http.MethodPost, "/api/v1/sboms", minimalSBOM, 201, 201, 201, 201},
		// Any authenticated user.
		{"list registries", http.MethodGet, "/api/v1/registries", "", 401, 200, 200, 200},
		{"get me", http.MethodGet, "/api/v1/users/me", "", 401, 200, 200, 200},
		// Member or admin only.
		{"create api key", http.MethodPost, "/api/v1/auth/keys", `{"name":"k"}`, 401, 403, 201, 201},
		{"list api keys", http.MethodGet, "/api/v1/auth/keys", "", 401, 403, 200, 200},
		// Admin only.
		{"list users", http.MethodGet, "/api/v1/users", "", 401, 403, 403, 200},
		{"admin status", http.MethodGet, "/api/v1/admin/status", "", 401, 403, 403, 200},
		// Registry owner or admin (RequireRegistryOwner middleware).
		{"patch registry", http.MethodPatch, "/api/v1/registries/" + memberRegID, patchRegistryBody, 401, 403, 200, 200},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, tt := range []struct {
				label string
				key   string
				want  int
			}{
				{"anon", "", tc.anonWant},
				{"viewer", viewerKey, tc.viewerWant},
				{"member", memberKey, tc.memberWant},
				{"admin", adminKey, tc.adminWant},
			} {
				resp, err := doWithAuth(t, tc.method, srv.URL+tc.path, tc.body, tt.key)
				if err != nil {
					t.Errorf("[%s] request failed: %v", tt.label, err)
					continue
				}
				resp.Body.Close()
				if resp.StatusCode != tt.want {
					t.Errorf("[%s] %s %s: got %d, want %d", tt.label, tc.method, tc.path, resp.StatusCode, tt.want)
				}
			}
		})
	}

	// Registry creation requires unique names, so test each auth level separately.
	t.Run("create registry", func(t *testing.T) {
		for _, tt := range []struct {
			label string
			key   string
			want  int
		}{
			{"anon", "", http.StatusUnauthorized},
			{"viewer", viewerKey, http.StatusCreated},
			{"member", memberKey, http.StatusCreated},
			{"admin", adminKey, http.StatusCreated},
		} {
			resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/registries", registryBody("create-"+tt.label), tt.key)
			if err != nil {
				t.Errorf("[%s] request failed: %v", tt.label, err)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Errorf("[%s] POST /api/v1/registries: got %d, want %d", tt.label, resp.StatusCode, tt.want)
			}
		}
	})
}
