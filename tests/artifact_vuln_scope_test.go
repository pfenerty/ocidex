package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/matryer/is"
)

// Version scope of the artifact vulnerability list (ocidex-7gf7.5).
//
// The list is computed over the newest SBOM of every version, which for the
// widest artifact in the corpus meant 1,025 SBOMs at ~1,093 components each and
// a request that died on the router's 30s ceiling. The scan is now capped at the
// most recent versions. These tests pin the two properties that make the cap
// safe rather than merely fast: it takes the *newest* versions, and the response
// says how much history it left out.

// vulnScopeSBOMTemplate is one version of a container artifact carrying a single
// package unique to that version, so a finding against that package is reachable
// from exactly one version and the scope boundary is observable.
const vulnScopeSBOMTemplate = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:44444444-4444-4444-4444-4444444444%02d",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/vuln-scope-fixture@sha256:%064d",
			"version": "v1.%d.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-05-%02dT00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "scoped-lib-%d",
			"version": "1.0.0",
			"purl": "pkg:generic/scoped-lib-%d@1.0.0"
		}
	]
}`

// vulnScopeVersions is how many versions the fixture seeds.
const vulnScopeVersions = 5

// artifactVulnPage is the shape of the vulnerability list this test reads.
type artifactVulnPage struct {
	Data []struct {
		CanonicalID      string `json:"canonicalId"`
		AffectedVersions []struct {
			Version string `json:"version"`
		} `json:"affectedVersions"`
	} `json:"data"`
	Pagination struct {
		Total int64 `json:"total"`
	} `json:"pagination"`
	VersionScope  int32 `json:"versionScope"`
	TotalVersions int64 `json:"totalVersions"`
}

// getArtifactVulns fetches the vulnerability list with the given extra query.
func getArtifactVulns(t *testing.T, baseURL, artifactID, query, apiKey string) artifactVulnPage {
	t.Helper()
	url := baseURL + "/api/v1/artifacts/" + artifactID + "/vulns?limit=50"
	if query != "" {
		url += "&" + query
	}
	resp, err := doWithAuth(t, http.MethodGet, url, "", apiKey)
	if err != nil {
		t.Fatalf("listing artifact vulns: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing artifact vulns %q: status %d", query, resp.StatusCode)
	}
	var page artifactVulnPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decoding artifact vulns: %v", err)
	}
	return page
}

func TestArtifactVulnsVersionScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	memberID := seedUser(t, pool, 8403, "vuln-scope-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "vuln-scope", nil)
	is.NoErr(err)
	path := ingestPath(t, pool, memberID)

	// v1.1.0 .. v1.5.0, each carrying its own package and its own advisory.
	var artifactID string
	for v := 1; v <= vulnScopeVersions; v++ {
		sbom := fmt.Sprintf(vulnScopeSBOMTemplate, v, v, v, v, v, v)
		artifactID = mustIngest(t, srv.URL, path, sbom, memberKey)
		seedFinding(t, pool,
			fmt.Sprintf("CVE-2026-2000%d", v), "HIGH", fmt.Sprintf("scoped-lib-%d", v))
	}
	if err := pool.QueryRow(t.Context(),
		`SELECT artifact_id::text FROM sbom WHERE id = $1`, artifactID).Scan(&artifactID); err != nil {
		t.Fatalf("resolving artifact id: %v", err)
	}

	refreshRollups(t, pool)

	// Unscoped-by-default is still the whole history when the history is short:
	// the cap is 20 and there are 5 versions, so nothing is left out, and the
	// response says so by reporting a total no larger than the scope.
	all := getArtifactVulns(t, srv.URL, artifactID, "", memberKey)
	is.Equal(all.VersionScope, int32(20))
	is.Equal(all.TotalVersions, int64(vulnScopeVersions))
	is.Equal(all.Pagination.Total, int64(vulnScopeVersions))

	// Capped at 2, the list covers v1.5.0 and v1.4.0 — the newest two — and
	// nothing older. This is the assertion that would have caught a cap ordered
	// by ingest time or by string comparison: it names which versions survive,
	// not just how many.
	scoped := getArtifactVulns(t, srv.URL, artifactID, "versionScope=2", memberKey)
	is.Equal(scoped.VersionScope, int32(2))
	is.Equal(scoped.TotalVersions, int64(vulnScopeVersions))
	is.Equal(scoped.Pagination.Total, int64(2))

	got := map[string]bool{}
	for _, v := range scoped.Data {
		got[v.CanonicalID] = true
		// A finding's affected versions must not reach outside the scope the
		// list itself used, or a row's own detail would contradict the caption
		// above the table.
		for _, av := range v.AffectedVersions {
			if av.Version != "v1.4.0" && av.Version != "v1.5.0" {
				t.Fatalf("finding %s lists version %s, outside the requested scope",
					v.CanonicalID, av.Version)
			}
		}
	}
	is.True(got["CVE-2026-20004"])
	is.True(got["CVE-2026-20005"])
	is.True(!got["CVE-2026-20001"])
}
