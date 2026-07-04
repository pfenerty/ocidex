package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

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
		ID:       id,
		Summary:  "test vulnerability " + id,
		Severity: severity,
		Aliases:  []string{},
		Raw:      []byte("{}"),
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
		ID: "CVE-2021-0001", Summary: "critical vuln 1", Severity: "CRITICAL",
		Aliases: []string{}, Raw: []byte("{}"),
	})
	is.NoErr(err)
	err = store.UpsertVulnerability(t.Context(), vuln.Row{
		ID: "CVE-2021-0002", Summary: "critical vuln 2", Severity: "CRITICAL",
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

	components := compResp["data"].([]any)
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
