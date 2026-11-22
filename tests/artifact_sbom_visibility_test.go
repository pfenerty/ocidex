package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/matryer/is"
)

// TestArtifactCountsIgnoreInvisibleSBOMs pins the SBOM-level half of the
// visibility rule on the artifact-level counts. An artifact is visible when any
// namespace it appears in is, so a shared artifact can carry SBOMs from a
// private namespace the viewer cannot see. Those SBOMs must not be counted, and
// must not be picked as the artifact's latest version: doing either leaks a
// private version's existence and findings through a public artifact.
func TestArtifactCountsIgnoreInvisibleSBOMs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 8501, "split-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID.String(), "split", nil)
	is.NoErr(err)

	publicSrc := seedSource(t, pool, seedNamespace(t, pool, "split-public", ownerID, "public"), "upload", "ci")
	privateSrc := seedSource(t, pool, seedNamespace(t, pool, "split-private", ownerID, "private"), "upload", "ci")

	// v1.1.0 is public with a LOW finding; the newer v1.2.0 is private with a
	// CRITICAL one. Same subject name, so both land on one artifact.
	mustIngest(t, srv.URL, "/api/v1/sboms?source="+publicSrc,
		fmt.Sprintf(vulnScopeSBOMTemplate, 1, 1, 1, 1, 1, 1), ownerKey)
	sbomID := mustIngest(t, srv.URL, "/api/v1/sboms?source="+privateSrc,
		fmt.Sprintf(vulnScopeSBOMTemplate, 2, 2, 2, 2, 2, 2), ownerKey)
	seedFinding(t, pool, "CVE-2026-30001", "LOW", "scoped-lib-1")
	seedFinding(t, pool, "CVE-2026-30002", "CRITICAL", "scoped-lib-2")
	refreshRollups(t, pool)

	var artifactID string
	is.NoErr(pool.QueryRow(t.Context(),
		`SELECT artifact_id::text FROM sbom WHERE id = $1`, sbomID).Scan(&artifactID))

	type counts struct {
		SbomCount      int64
		Critical, Low  int
		SubjectVersion string
	}
	read := func(apiKey string) counts {
		t.Helper()
		var list struct {
			Data []struct {
				ID        string `json:"id"`
				SbomCount int64  `json:"sbomCount"`
				Vulns     *struct {
					Critical int `json:"critical"`
					Low      int `json:"low"`
				} `json:"vulns"`
			} `json:"data"`
		}
		getJSON(t, srv.URL+"/api/v1/artifacts?sufficient=false", apiKey, &list)
		is.Equal(len(list.Data), 1)
		is.Equal(list.Data[0].ID, artifactID)
		is.True(list.Data[0].Vulns != nil)

		var summary struct {
			Summary *struct {
				Critical int `json:"critical"`
				Low      int `json:"low"`
			} `json:"summary"`
			SubjectVersion string `json:"subjectVersion"`
		}
		getJSON(t, srv.URL+"/api/v1/artifacts/"+artifactID+"/vuln-summary", apiKey, &summary)
		is.True(summary.Summary != nil)
		// The tile and the list row count the same SBOM.
		is.Equal(summary.Summary.Critical, list.Data[0].Vulns.Critical)
		is.Equal(summary.Summary.Low, list.Data[0].Vulns.Low)

		return counts{
			SbomCount:      list.Data[0].SbomCount,
			Critical:       summary.Summary.Critical,
			Low:            summary.Summary.Low,
			SubjectVersion: summary.SubjectVersion,
		}
	}

	is.Equal(read(ownerKey), counts{SbomCount: 2, Critical: 1, SubjectVersion: "v1.2.0"})
	is.Equal(read(""), counts{SbomCount: 1, Low: 1, SubjectVersion: "v1.1.0"})
}

// getJSON GETs url as apiKey (anonymous when empty) and decodes a 200 body.
func getJSON(t *testing.T, url, apiKey string, out any) {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, url, "", apiKey)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decoding %s: %v", url, err)
	}
}
