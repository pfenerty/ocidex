package tests

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/service"
)

const testSessionSecret = "test-session-secret-padded-32b!" // 32 bytes

const patchRegistryBody = `{"name":"updated","type":"generic","url":"registry.example.com","insecure":false,"enabled":true,"repositories":[],"repository_patterns":[],"tag_patterns":[]}`

// registryBody uses scan_mode=webhook so the test doesn't require
// REGISTRY_POLLER_ENABLED=true (poll/both modes are gated on that env var).
func registryBody(name string) string {
	return `{"name":"` + name + `","type":"generic","url":"registry.example.com","insecure":false,"visibility":"public","scan_mode":"webhook","repositories":[],"repository_patterns":[],"tag_patterns":[]}`
}

func setupServerWithAuth(t *testing.T, pool *pgxpool.Pool) (*httptest.Server, service.AuthService) {
	t.Helper()
	srv, authSvc, _ := setupServerWithStats(t, pool)
	return srv, authSvc
}

// setupServerWithStats is setupServerWithAuth plus the server's search service.
//
// The dashboard-stats endpoint serves the TTL cache and no longer computes on a
// miss, so a test asserting on stats has to warm that cache — and it has to warm
// the very instance the server reads, which means getting hold of it here.
func setupServerWithStats(t *testing.T, pool *pgxpool.Pool) (*httptest.Server, service.AuthService, service.SearchService) {
	t.Helper()
	cfg := &config.Config{SessionSecret: testSessionSecret}
	authSvc := service.NewAuthService(pool, cfg, event.NewBus(slog.Default()))
	sbomSvc := service.NewSBOMService(pool, nil, nil)
	searchSvc := service.NewSearchService(pool)
	registrySvc := service.NewRegistryService(pool)
	// Ingest resolves its namespace through the source (ADR-039), so both of
	// these are on the write path, not just the /namespaces and /sources routes.
	namespaceSvc := service.NewNamespaceService(pool)
	sourceSvc := service.NewSourceService(pool)
	// The job services are wired so the /jobs and /enrichment-jobs feeds are
	// exercisable; they are owner-scoped reads, not admin-only ones
	// (ocidex-998g.1).
	jobSvc := service.NewJobService(pool)
	enrichJobSvc := service.NewEnrichJobService(pool, "")
	handler := api.NewHandler(sbomSvc, searchSvc, authSvc, registrySvc,
		namespaceSvc, sourceSvc, jobSvc, enrichJobSvc, pool, nil, cfg)
	router := api.NewRouter(handler, "*", "", "")
	return httptest.NewServer(router), authSvc, searchSvc
}

// warmStats populates the dashboard-stats cache for the anonymous scope, which
// is what an unauthenticated GET /api/v1/stats reads.
func warmStats(t *testing.T, searchSvc service.SearchService) {
	t.Helper()
	if _, err := searchSvc.WarmDashboardStats(t.Context(), service.VisibilityFilter{}); err != nil {
		t.Fatalf("warming dashboard stats: %v", err)
	}
}

// refreshRollups rebuilds the list-page rollup tables synchronously.
//
// In the running server a background refresher does this, so a component
// ingested seconds ago is not on the Components page yet. Tests that assert on
// list endpoints immediately after an ingest need the rollups current; running
// the real refresher is what makes those assertions test the production read
// path rather than a fixture.
func refreshRollups(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ran, err := service.NewRollupRefresher(pool, 0, slog.Default()).RefreshNow(t.Context())
	if err != nil {
		t.Fatalf("refreshing rollups: %v", err)
	}
	if !ran {
		t.Fatal("refreshing rollups: advisory lock unexpectedly held by another pass")
	}
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

// mustIngest POSTs an SBOM to path and returns the new SBOM's id, failing the
// test with the server's error body when the status is not 201.
//
// Asserting bare status equality discards that body, and the two ingest
// validation gates both report which field they rejected: validateBOM returns
// 422 with an `errors[]` array, validateContainerRequired returns 400 with the
// missing field names in `detail`. Losing it turns a stale fixture into an
// unattributable "400 != 201" (ocidex-784).
func mustIngest(t *testing.T, baseURL, path, sbomJSON, apiKey string) string {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodPost, baseURL+path, sbomJSON, apiKey)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("ingest: status %d (want 201): %s", resp.StatusCode, body)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("ingest: decode response: %v", err)
	}
	return out.ID
}

func TestAuthBoundaries(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

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

	adminKey, err := authSvc.CreateAPIKey(ctx, adminID, "test", "read-write")
	is.NoErr(err)
	memberKey, err := authSvc.CreateAPIKey(ctx, memberID, "test", "read-write")
	is.NoErr(err)
	viewerKey, err := authSvc.CreateAPIKey(ctx, viewerID, "test", "read-write")
	is.NoErr(err)

	// Create a registry owned by member; used for owner-middleware cases.
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/registries", registryBody("owner-reg"), memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var regResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&regResp))
	resp.Body.Close()
	memberRegID := regResp["id"].(string)

	// A second registry owned by admin, so ingest can be aimed at a namespace
	// the member does not own.
	resp, err = doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/registries", registryBody("admin-reg"), adminKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	is.NoErr(json.NewDecoder(resp.Body).Decode(&regResp))
	resp.Body.Close()
	adminRegID := regResp["id"].(string)

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
		// SBOM ingest — requires member or admin role, plus a source in a
		// namespace the caller owns (ADR-039). Admin manages every namespace,
		// so it lands in the member's namespace too.
		{"ingest sbom", http.MethodPost, "/api/v1/sboms?source=" + memberRegID, minimalSBOM, 401, 403, 201, 201},
		// No source means no owner, and an SBOM cannot exist unowned.
		{"ingest without source", http.MethodPost, "/api/v1/sboms", minimalSBOM, 401, 403, 400, 400},
		// Naming someone else's namespace is a 403, not a quiet reassignment.
		{"ingest into another's namespace", http.MethodPost, "/api/v1/sboms?source=" + adminRegID,
			alpineSBOM, 401, 403, 403, 201},
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
