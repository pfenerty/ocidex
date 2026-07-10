package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/vuln"
)

const (
	addUserPurl = "pkg:deb/ubuntu/adduser@3.118ubuntu2?arch=all&distro=ubuntu-24.04"
	aptPurl     = "pkg:deb/ubuntu/apt@2.7.14?arch=arm64&distro=ubuntu-24.04"
)

// seedVuln inserts one vulnerability record and wires it to a purl.
func seedVuln(t *testing.T, store *vuln.PGStore, id, severity, purl string) {
	t.Helper()
	err := store.UpsertVulnerability(t.Context(), vuln.Row{
		ID:          id,
		CanonicalID: id,
		Summary:     "test vulnerability " + id,
		Severity:    severity,
		Aliases:     []string{},
		Raw:         []byte("{}"),
	})
	if err != nil {
		t.Fatalf("upsert vulnerability %s: %v", id, err)
	}
	err = store.ReplacePackageVulns(t.Context(), purl, []vuln.PackageVulnRef{
		{VulnerabilityID: id},
	})
	if err != nil {
		t.Fatalf("replace package vulns for %s: %v", purl, err)
	}
}

// TestVulnSBOMSummaryJoin is the core round-trip: seed vulns after SBOM ingest,
// then assert the join surfaces correctly through every read endpoint.
func TestVulnSBOMSummaryJoin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	store := vuln.NewPGStore(pool)

	memberID := seedUser(t, pool, 8001, "vuln-test-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "vuln-test", "read-write")
	is.NoErr(err)

	// Ingest SBOM — at this point no vulns exist, so summary should be absent.
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", minimalSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingestResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingestResp))
	resp.Body.Close()
	sbomID := ingestResp["id"].(string)

	// Confirm no vulnSummary before seeding.
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var sbomDetail map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&sbomDetail))
	resp.Body.Close()
	is.True(sbomDetail["vulnSummary"] == nil)

	// Seed: 2 CRITICAL vulns for adduser, 1 HIGH vuln for apt.
	// adduser has 2 separate CVEs → ReplacePackageVulns is called once per CVE
	// because each call replaces the full purl mapping. We must set both in one call.
	err = store.UpsertVulnerability(t.Context(), vuln.Row{
		ID: "CVE-2021-0001", CanonicalID: "CVE-2021-0001", Summary: "critical vuln 1", Severity: "CRITICAL",
		Aliases: []string{}, Raw: []byte("{}"),
	})
	is.NoErr(err)
	err = store.UpsertVulnerability(t.Context(), vuln.Row{
		ID: "CVE-2021-0002", CanonicalID: "CVE-2021-0002", Summary: "critical vuln 2", Severity: "CRITICAL",
		Aliases: []string{}, Raw: []byte("{}"),
	})
	is.NoErr(err)
	err = store.ReplacePackageVulns(t.Context(), addUserPurl, []vuln.PackageVulnRef{
		{VulnerabilityID: "CVE-2021-0001"},
		{VulnerabilityID: "CVE-2021-0002"},
	})
	is.NoErr(err)

	seedVuln(t, store, "CVE-2022-0001", "HIGH", aptPurl)

	// --- Assert GET /api/v1/sboms/{id} vuln summary ---
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	is.NoErr(json.NewDecoder(resp.Body).Decode(&sbomDetail))
	resp.Body.Close()

	vs := sbomDetail["vulnSummary"].(map[string]any)
	is.Equal(vs["critical"], float64(2))
	is.Equal(vs["high"], float64(1))
	is.Equal(vs["total"], float64(3))

	// --- Assert GET /api/v1/sboms/{id}/components component decoration ---
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s/components", srv.URL, sbomID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var compResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&compResp))
	resp.Body.Close()

	components := compResp["components"].([]any)
	is.True(len(components) == 2)

	byName := map[string]map[string]any{}
	for _, c := range components {
		cm := c.(map[string]any)
		byName[cm["name"].(string)] = cm
	}
	adduserComp := byName["adduser"]
	aptComp := byName["apt"]
	is.True(adduserComp != nil)
	is.True(aptComp != nil)
	is.Equal(adduserComp["vulnCount"], float64(2))
	is.Equal(adduserComp["maxSeverity"], "CRITICAL")
	is.Equal(aptComp["vulnCount"], float64(1))
	is.Equal(aptComp["maxSeverity"], "HIGH")

	// --- Assert GET /api/v1/vulns lists all seeded CVEs ---
	resp, err = doGet(t, srv.URL+"/api/v1/vulns")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var vulnsResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&vulnsResp))
	resp.Body.Close()
	is.True(len(vulnsResp["data"].([]any)) >= 3)

	// --- Assert GET /api/v1/vulns/{id} returns detail for a specific CVE ---
	resp, err = doGet(t, srv.URL+"/api/v1/vulns/CVE-2021-0001")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var vulnDetailResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&vulnDetailResp))
	resp.Body.Close()
	vd := vulnDetailResp["vulnerability"].(map[string]any)
	is.Equal(vd["id"], "CVE-2021-0001")
	is.Equal(vd["severity"], "CRITICAL")
	is.Equal(vd["summary"], "critical vuln 1")

	// --- Assert GET /api/v1/artifacts/{id}/vuln-summary ---
	// Resolve the artifact ID from the SBOM detail.
	artifactID := sbomDetail["artifactId"].(string)
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/artifacts/%s/vuln-summary", srv.URL, artifactID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var artVulnResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&artVulnResp))
	resp.Body.Close()
	artSummary := artVulnResp["summary"].(map[string]any)
	is.Equal(artSummary["critical"], float64(2))
	is.Equal(artSummary["high"], float64(1))
	is.Equal(artSummary["total"], float64(3))
}

// TestVulnAliasDedup asserts that two OSV records sharing a canonical_id (e.g.
// GO-2024-xxxx + GHSA-yyyy both aliasing CVE-2024-0001) are counted as one finding
// in SBOM/artifact summaries, dashboard stats, and the top-vulns list.
func TestVulnAliasDedup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	store := vuln.NewPGStore(pool)

	memberID := seedUser(t, pool, 8003, "alias-dedup-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "alias-dedup-test", "read-write")
	is.NoErr(err)

	// Ingest SBOM.
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", minimalSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingestResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingestResp))
	resp.Body.Close()
	sbomID := ingestResp["id"].(string)

	// Seed two aliased records for the same real-world CVE, both mapped to addUserPurl.
	// GO-2024-alias and GHSA-alias are different OSV IDs sharing canonical_id=CVE-2024-0042.
	err = store.UpsertVulnerability(t.Context(), vuln.Row{
		ID:          "GO-2024-alias",
		CanonicalID: "CVE-2024-0042",
		Summary:     "alias vuln GO record",
		Severity:    "CRITICAL",
		Aliases:     []string{"CVE-2024-0042", "GHSA-alias"},
		Raw:         []byte("{}"),
	})
	is.NoErr(err)
	err = store.UpsertVulnerability(t.Context(), vuln.Row{
		ID:          "GHSA-alias",
		CanonicalID: "CVE-2024-0042",
		Summary:     "alias vuln GHSA record",
		Severity:    "CRITICAL",
		Aliases:     []string{"CVE-2024-0042", "GO-2024-alias"},
		Raw:         []byte("{}"),
	})
	is.NoErr(err)
	err = store.ReplacePackageVulns(t.Context(), addUserPurl, []vuln.PackageVulnRef{
		{VulnerabilityID: "GO-2024-alias"},
		{VulnerabilityID: "GHSA-alias"},
	})
	is.NoErr(err)

	// SBOM vuln summary must show critical=1, total=1 (not 2).
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var sbomDetail map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&sbomDetail))
	resp.Body.Close()
	vs := sbomDetail["vulnSummary"].(map[string]any)
	is.Equal(vs["critical"], float64(1))
	is.Equal(vs["total"], float64(1))
	artifactID := sbomDetail["artifactId"].(string)

	// Artifact vuln summary must also show critical=1.
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/artifacts/%s/vuln-summary", srv.URL, artifactID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var artVulnResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&artVulnResp))
	resp.Body.Close()
	artSummary := artVulnResp["summary"].(map[string]any)
	is.Equal(artSummary["critical"], float64(1))
	is.Equal(artSummary["total"], float64(1))

	// Top-vulns list must show exactly 1 row for this canonical_id (not 2 alias rows).
	resp, err = doGet(t, srv.URL+"/api/v1/vulns")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var vulnsResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&vulnsResp))
	resp.Body.Close()
	rows := vulnsResp["data"].([]any)
	canonicalCount := 0
	for _, r := range rows {
		rm := r.(map[string]any)
		if rm["canonicalId"] == "CVE-2024-0042" {
			canonicalCount++
		}
	}
	is.Equal(canonicalCount, 1)

	// Dashboard stats must count 1 vuln (not 2 alias rows).
	resp, err = doGet(t, srv.URL+"/api/v1/stats")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var statsResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&statsResp))
	resp.Body.Close()
	is.Equal(statsResp["vuln_count"], float64(1))
}

// TestVulnAliasDetailResolution verifies that GET /api/v1/vulns/{id} resolves by
// canonical_id and by an alias-only id, surfacing affected artifacts/components
// across aliased records.
//
// Scenario: addUserPurl is mapped to GO-2024-0001 only. Visiting the GHSA alias,
// the canonical CVE id, or a pure alias-only id (never its own id or canonical_id,
// only present inside another record's aliases array) must still resolve.
func TestVulnAliasDetailResolution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	store := vuln.NewPGStore(pool)

	memberID := seedUser(t, pool, 8004, "alias-detail-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "alias-detail-test", "read-write")
	is.NoErr(err)

	// Ingest SBOM to create artifact + component rows.
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", minimalSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	resp.Body.Close()

	// Two aliased vuln records sharing canonical_id=CVE-2024-0001.
	// The purl is mapped to the GO record only — the GHSA and CVE paths must still resolve.
	err = store.UpsertVulnerability(t.Context(), vuln.Row{
		ID:          "GO-2024-0001",
		CanonicalID: "CVE-2024-0001",
		Summary:     "alias detail test GO record",
		Severity:    "HIGH",
		Aliases:     []string{"CVE-2024-0001", "GHSA-2024-0001", "SNYK-2024-0001"},
		Raw:         []byte("{}"),
	})
	is.NoErr(err)
	err = store.UpsertVulnerability(t.Context(), vuln.Row{
		ID:          "GHSA-2024-0001",
		CanonicalID: "CVE-2024-0001",
		Summary:     "alias detail test GHSA record",
		Severity:    "HIGH",
		Aliases:     []string{"CVE-2024-0001", "GO-2024-0001"},
		Raw:         []byte("{}"),
	})
	is.NoErr(err)
	err = store.ReplacePackageVulns(t.Context(), addUserPurl, []vuln.PackageVulnRef{
		{VulnerabilityID: "GO-2024-0001"},
	})
	is.NoErr(err)

	// GET by native GO id — baseline, must always work.
	resp, err = doGet(t, srv.URL+"/api/v1/vulns/GO-2024-0001")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var detail map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&detail))
	resp.Body.Close()
	is.Equal(detail["vulnerability"].(map[string]any)["id"], "GO-2024-0001")
	goComponents := detail["affectedComponents"].([]any)
	is.True(len(goComponents) == 1)
	is.Equal(goComponents[0].(map[string]any)["name"], "adduser")

	// GET by GHSA alias — affected components must aggregate via canonical_id.
	resp, err = doGet(t, srv.URL+"/api/v1/vulns/GHSA-2024-0001")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	is.NoErr(json.NewDecoder(resp.Body).Decode(&detail))
	resp.Body.Close()
	is.Equal(detail["vulnerability"].(map[string]any)["id"], "GHSA-2024-0001")
	ghsaComponents := detail["affectedComponents"].([]any)
	is.True(len(ghsaComponents) == 1)
	is.Equal(ghsaComponents[0].(map[string]any)["name"], "adduser")

	// GET by canonical CVE id — was 404 before fix.
	resp, err = doGet(t, srv.URL+"/api/v1/vulns/CVE-2024-0001")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	is.NoErr(json.NewDecoder(resp.Body).Decode(&detail))
	resp.Body.Close()
	is.Equal(detail["vulnerability"].(map[string]any)["canonicalId"], "CVE-2024-0001")
	cveComponents := detail["affectedComponents"].([]any)
	is.True(len(cveComponents) == 1)
	is.Equal(cveComponents[0].(map[string]any)["name"], "adduser")

	// GET by a pure alias-only id — never its own id or canonical_id, present
	// only inside GO-2024-0001's aliases array. 404 before the ANY(aliases) fix.
	resp, err = doGet(t, srv.URL+"/api/v1/vulns/SNYK-2024-0001")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	is.NoErr(json.NewDecoder(resp.Body).Decode(&detail))
	resp.Body.Close()
	is.Equal(detail["vulnerability"].(map[string]any)["id"], "GO-2024-0001")
	snykComponents := detail["affectedComponents"].([]any)
	is.True(len(snykComponents) == 1)
	is.Equal(snykComponents[0].(map[string]any)["name"], "adduser")
}

// TestVulnLiveJoinSemantics proves the vuln join is live: a CVE seeded after
// SBOM ingest appears immediately in the SBOM's vuln summary without re-ingest.
func TestVulnLiveJoinSemantics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	store := vuln.NewPGStore(pool)

	memberID := seedUser(t, pool, 8002, "vuln-live-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "vuln-live-test", "read-write")
	is.NoErr(err)

	// Ingest SBOM.
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", minimalSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingestResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingestResp))
	resp.Body.Close()
	sbomID := ingestResp["id"].(string)

	// No vulns yet — summary must be absent.
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var detail map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&detail))
	resp.Body.Close()
	is.True(detail["vulnSummary"] == nil)

	// Seed one CRITICAL vuln for adduser — no SBOM re-ingest.
	seedVuln(t, store, "CVE-2023-9999", "CRITICAL", addUserPurl)

	// Summary must now reflect the new finding.
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	is.NoErr(json.NewDecoder(resp.Body).Decode(&detail))
	resp.Body.Close()
	vs := detail["vulnSummary"].(map[string]any)
	is.Equal(vs["critical"], float64(1))
	is.Equal(vs["total"], float64(1))
}

// TestVulnDuplicatePurlSummaryParity verifies that GetSBOMVulnSummary and
// GetArtifactVulnSummary return identical counts when the same purl appears in
// multiple component rows of one SBOM (regression for ocidex-0le.3).
func TestVulnDuplicatePurlSummaryParity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	store := vuln.NewPGStore(pool)

	memberID := seedUser(t, pool, 8005, "dup-purl-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "dup-purl-test", "read-write")
	is.NoErr(err)

	// Ingest SBOM with two components sharing addUserPurl.
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", duplicatePurlSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingestResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingestResp))
	resp.Body.Close()
	sbomID := ingestResp["id"].(string)

	// Seed one CRITICAL vuln for the duplicate purl.
	seedVuln(t, store, "CVE-2024-dup-0001", "CRITICAL", addUserPurl)

	// --- SBOM summary (GetSBOMVulnSummary) ---
	resp, err = doWithAuth(t, http.MethodGet, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomID), "", memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var sbomDetail map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&sbomDetail))
	resp.Body.Close()
	sbomSummary := sbomDetail["vulnSummary"].(map[string]any)
	is.Equal(sbomSummary["critical"], float64(1))
	is.Equal(sbomSummary["total"], float64(1))

	// --- Artifact summary (GetArtifactVulnSummary) ---
	artifactID := sbomDetail["artifactId"].(string)
	resp, err = doWithAuth(t, http.MethodGet, fmt.Sprintf("%s/api/v1/artifacts/%s/vuln-summary", srv.URL, artifactID), "", memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var artResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&artResp))
	resp.Body.Close()
	artSummary := artResp["summary"].(map[string]any)

	// Both queries must agree: one purl → one finding, not two.
	is.Equal(artSummary["critical"], sbomSummary["critical"])
	is.Equal(artSummary["total"], sbomSummary["total"])
	is.Equal(artSummary["critical"], float64(1))
	is.Equal(artSummary["total"], float64(1))
}

// TestPurlVulnStateSkipsCleanPurls verifies a purl checked-and-clean against
// OSV (ReplacePackageVulns called with no refs) is excluded from the
// "unknown" purl queries used to drive further OSV lookups, but reappears
// once its checked_at falls outside the staleness horizon (regression
// ocidex-0le.17: clean purls were indistinguishable from never-checked ones).
func TestPurlVulnStateSkipsCleanPurls(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	store := vuln.NewPGStore(pool)

	memberID := seedUser(t, pool, 8006, "purl-state-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "purl-state-test", "read-write")
	is.NoErr(err)

	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", minimalSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingestResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingestResp))
	resp.Body.Close()
	var sbomID pgtype.UUID
	is.NoErr(sbomID.Scan(ingestResp["id"].(string)))

	// Before any OSV check, addUserPurl is unknown both per-SBOM and globally.
	unknownForSBOM, err := store.ListUnknownPurlsForSBOM(t.Context(), sbomID)
	is.NoErr(err)
	is.True(slices.Contains(unknownForSBOM, addUserPurl))

	unknownGlobal, err := store.ListUnknownComponentPurls(t.Context())
	is.NoErr(err)
	is.True(slices.Contains(unknownGlobal, addUserPurl))

	// Simulate an OSV lookup that came back clean.
	err = store.ReplacePackageVulns(t.Context(), addUserPurl, nil)
	is.NoErr(err)

	// The purl is now checked-clean: it must drop out of both unknown lists.
	unknownForSBOM, err = store.ListUnknownPurlsForSBOM(t.Context(), sbomID)
	is.NoErr(err)
	is.True(!slices.Contains(unknownForSBOM, addUserPurl))

	unknownGlobal, err = store.ListUnknownComponentPurls(t.Context())
	is.NoErr(err)
	is.True(!slices.Contains(unknownGlobal, addUserPurl))

	// Age the checked_at past the staleness horizon (24h) to simulate a
	// clean purl that's due for re-verification.
	_, err = pool.Exec(t.Context(),
		"UPDATE purl_vuln_state SET checked_at = now() - interval '25 hours' WHERE purl = $1",
		addUserPurl)
	is.NoErr(err)

	unknownForSBOM, err = store.ListUnknownPurlsForSBOM(t.Context(), sbomID)
	is.NoErr(err)
	is.True(slices.Contains(unknownForSBOM, addUserPurl))

	unknownGlobal, err = store.ListUnknownComponentPurls(t.Context())
	is.NoErr(err)
	is.True(slices.Contains(unknownGlobal, addUserPurl))
}
