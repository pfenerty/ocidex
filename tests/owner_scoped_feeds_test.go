package tests

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/vuln"
)

// The four operational feeds this file covers were admin-only (or authenticated
// but unscoped, which leaked every tenant's repositories to any signed-in user).
// ocidex-998g.1 rekeyed them to visible_namespace_ids: an admin still gets the
// cross-tenant view from the same endpoint, and a namespace owner gets exactly
// their own rows. The property under test is that a *third* party — signed in,
// not an admin, not the owner — gets zero rows from all four.

// seedRegistryInNamespace inserts the namespace/source/registry triple that a
// scan job hangs off. Registry, source, and namespace do not share an id here:
// a namespace holds many sources (ADR-039), and reusing one id across all three
// would hide a join bug that only shows up when they differ.
func seedRegistryInNamespace(t *testing.T, pool *pgxpool.Pool, nsID, name string) string {
	t.Helper()
	srcID := seedSource(t, pool, nsID, "oci_registry", name)
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO registry (id, url, type, enabled)
		VALUES ($1, $2, 'generic', true)
	`, srcID, "registry."+name+".example.com"); err != nil {
		t.Fatalf("insert registry %q: %v", name, err)
	}
	return srcID
}

// seedScanJob inserts a succeeded scan_jobs row against a registry.
func seedScanJob(t *testing.T, pool *pgxpool.Pool, registryID, repo string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO scan_jobs (registry_id, repository, digest, state)
		VALUES ($1, $2, $3, 'succeeded')
	`, registryID, repo, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatalf("insert scan job for %q: %v", repo, err)
	}
}

// sbomIDInNamespace returns the id of the single SBOM in a namespace.
func sbomIDInNamespace(t *testing.T, pool *pgxpool.Pool, nsID string) pgtype.UUID {
	t.Helper()
	var id pgtype.UUID
	if err := pool.QueryRow(t.Context(),
		`SELECT id FROM sbom WHERE namespace_id = $1 LIMIT 1`, nsID).Scan(&id); err != nil {
		t.Fatalf("sbom in namespace %s: %v", nsID, err)
	}
	return id
}

// seedEnrichmentJob inserts a failed enrichment_jobs row against an SBOM.
func seedEnrichmentJob(t *testing.T, pool *pgxpool.Pool, sbomID pgtype.UUID, enricher string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO enrichment_jobs (sbom_id, enricher_name, state)
		VALUES ($1, $2, 'failed')
	`, sbomID, enricher); err != nil {
		t.Fatalf("insert enrichment job: %v", err)
	}
}

// seedDriftEvent inserts a provenance_drift_events row against an SBOM.
func seedDriftEvent(t *testing.T, pool *pgxpool.Pool, sbomID pgtype.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO provenance_drift_events (sbom_id, previous_status, new_status, reason)
		VALUES ($1, 'verified', 'unsigned', 'reverification_failed')
	`, sbomID); err != nil {
		t.Fatalf("insert drift event: %v", err)
	}
}

// feedRowCount GETs a feed and reports how many rows came back under "data".
func feedRowCount(t *testing.T, baseURL, path, apiKey string) int {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+path, "", apiKey)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", path, resp.StatusCode)
	}
	var body struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return len(body.Data)
}

// TestOwnerScopedFeedsExcludeNonOwners is the acceptance criterion for
// ocidex-998g.1: the drift feed, trust summary, scan-job list and
// enrichment-job list all answer a namespace owner with their own rows and a
// stranger with zero, without either caller holding the admin role.
func TestOwnerScopedFeedsExcludeNonOwners(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7301, "feed-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", "read-write")
	is.NoErr(err)
	strangerID := seedUser(t, pool, 7302, "feed-stranger", "member")
	strangerKey, err := authSvc.CreateAPIKey(t.Context(), strangerID, "stranger", "read-write")
	is.NoErr(err)
	adminID := seedUser(t, pool, 7303, "feed-admin", "admin")
	adminKey, err := authSvc.CreateAPIKey(t.Context(), adminID, "admin", "read-write")
	is.NoErr(err)

	// One private namespace owned by ownerID, with an SBOM to hang jobs off.
	nsID := seedNamespace(t, pool, "feed-ns", ownerID, "private")
	uploadSrc := seedSource(t, pool, nsID, "upload", "ci")
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms?source="+uploadSrc, minimalSBOM, ownerKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	resp.Body.Close()

	sbomID := sbomIDInNamespace(t, pool, nsID)
	regID := seedRegistryInNamespace(t, pool, nsID, "owned")
	seedScanJob(t, pool, regID, "ubuntu")
	seedEnrichmentJob(t, pool, sbomID, "provenance")
	seedDriftEvent(t, pool, sbomID)

	const (
		driftFeed    = "/api/v1/registries/drift-feed"
		trustSummary = "/api/v1/registries/trust-summary"
		scanJobs     = "/api/v1/jobs"
		enrichJobs   = "/api/v1/enrichment-jobs"
		enrichSummry = "/api/v1/enrichment-jobs/summary"
	)

	// The owner reads every feed without holding the admin role.
	is.Equal(feedRowCount(t, srv.URL, driftFeed, ownerKey), 1)
	is.Equal(feedRowCount(t, srv.URL, scanJobs, ownerKey), 1)
	is.Equal(feedRowCount(t, srv.URL, enrichJobs, ownerKey), 1)
	is.Equal(feedRowCount(t, srv.URL, enrichSummry, ownerKey), 1)
	// Trust summary counts artifacts whose SBOM arrived through an OCI source;
	// this one arrived by upload, so the owner's row count is legitimately 0.
	// The assertion that matters is that the call succeeds rather than 403s.
	is.Equal(feedRowCount(t, srv.URL, trustSummary, ownerKey), 0)

	// A signed-in stranger gets zero rows from every one of them.
	is.Equal(feedRowCount(t, srv.URL, driftFeed, strangerKey), 0)
	is.Equal(feedRowCount(t, srv.URL, scanJobs, strangerKey), 0)
	is.Equal(feedRowCount(t, srv.URL, enrichJobs, strangerKey), 0)
	is.Equal(feedRowCount(t, srv.URL, enrichSummry, strangerKey), 0)
	is.Equal(feedRowCount(t, srv.URL, trustSummary, strangerKey), 0)

	// The admin keeps the unscoped cross-tenant view.
	is.Equal(feedRowCount(t, srv.URL, driftFeed, adminKey), 1)
	is.Equal(feedRowCount(t, srv.URL, scanJobs, adminKey), 1)
	is.Equal(feedRowCount(t, srv.URL, enrichJobs, adminKey), 1)
	is.Equal(feedRowCount(t, srv.URL, enrichSummry, adminKey), 1)

	// Flipping the namespace public exposes the same rows to the stranger —
	// visibility is read from namespace on every request, not cached.
	_, err = pool.Exec(t.Context(), `UPDATE namespace SET visibility = 'public' WHERE id = $1`, nsID)
	is.NoErr(err)
	is.Equal(feedRowCount(t, srv.URL, driftFeed, strangerKey), 1)
	is.Equal(feedRowCount(t, srv.URL, scanJobs, strangerKey), 1)
	is.Equal(feedRowCount(t, srv.URL, enrichJobs, strangerKey), 1)

	// ocidex-998g.5: the owned variants stay narrow exactly where the
	// visibility-filtered siblings widen. The namespace is public now, so the
	// stranger and the admin both see the drift event on /registries/drift-feed
	// — but neither owns the namespace, so /users/me/drift-feed is empty for
	// both, including the admin, whose role buys no widening here.
	const (
		myDriftFeed = "/api/v1/users/me/drift-feed"
		myVulns     = "/api/v1/users/me/vulns"
	)
	is.Equal(feedRowCount(t, srv.URL, myDriftFeed, ownerKey), 1)
	is.Equal(feedRowCount(t, srv.URL, myDriftFeed, strangerKey), 0)
	is.Equal(feedRowCount(t, srv.URL, myDriftFeed, adminKey), 0)

	// Same property for exposure. The vulnerability hits a package in the
	// owner's now-public SBOM, so it is on everybody's /vulns and on nobody
	// else's /users/me/vulns.
	seedVuln(t, vuln.NewPGStore(pool), "CVE-2098-0001", "HIGH", addUserPurl)
	refreshRollups(t, pool)
	is.Equal(feedRowCount(t, srv.URL, "/api/v1/vulns", strangerKey), 1)
	is.Equal(feedRowCount(t, srv.URL, myVulns, ownerKey), 1)
	is.Equal(feedRowCount(t, srv.URL, myVulns, strangerKey), 0)
	is.Equal(feedRowCount(t, srv.URL, myVulns, adminKey), 0)
}

// TestGetScanJobHidesOtherTenantsJob covers the single-row read: a job outside
// the caller's visible namespaces must 404 rather than leak its repository and
// digest to any authenticated caller.
func TestGetScanJobHidesOtherTenantsJob(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7401, "job-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", "read-write")
	is.NoErr(err)
	strangerID := seedUser(t, pool, 7402, "job-stranger", "member")
	strangerKey, err := authSvc.CreateAPIKey(t.Context(), strangerID, "stranger", "read-write")
	is.NoErr(err)

	nsID := seedNamespace(t, pool, "job-ns", ownerID, "private")
	regID := seedRegistryInNamespace(t, pool, nsID, "owned")
	seedScanJob(t, pool, regID, "ubuntu")

	var jobID string
	err = pool.QueryRow(t.Context(),
		`SELECT id::text FROM scan_jobs WHERE registry_id = $1`, regID).Scan(&jobID)
	is.NoErr(err)

	get := func(key string) int {
		t.Helper()
		resp, err := doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/jobs/"+jobID, "", key)
		is.NoErr(err)
		defer resp.Body.Close()
		return resp.StatusCode
	}

	is.Equal(get(ownerKey), http.StatusOK)
	is.Equal(get(strangerKey), http.StatusNotFound)
}
