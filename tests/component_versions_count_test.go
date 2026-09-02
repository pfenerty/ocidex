package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/matryer/is"
)

// Counts on /components/versions (ocidex-7gf7.6).
//
// The three corpus-wide figures under that page — the row total the pager uses,
// the version count and the artifact count — came from a query that timed out
// for the most widely used package names: sbom_visible() is opaque to the
// planner, which drove a nested loop from a sequential scan of every visible
// SBOM and probed the component index once per row (17.2s for name=stdlib
// against a 30s ceiling). The fix matches components first in a MATERIALIZED
// CTE and hash-joins sbom to them, which moves the same three numbers to 146ms.
//
// That rewrite moved the component filters into the CTE and left visibility on
// the outer join, so what needs pinning is not the speed — a fixture small
// enough to run in CI cannot reproduce the plan — but that the numbers did not
// change: a private namespace must still be excluded, and each filter must
// still narrow the count.

// countSBOMTemplate is a container SBOM carrying one shared package name plus a
// second package unique to the SBOM, parameterised by serial, digest, subject
// version and the shared package's version.
const countSBOMTemplate = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:88888888-8888-8888-8888-8888888888%02d",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/count-fixture-%d@sha256:%064d",
			"version": "v1.0.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-06-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "counted-lib",
			"version": "%s",
			"purl": "pkg:generic/counted-lib@%s"
		},
		{
			"type": "application",
			"name": "counted-lib",
			"group": "tools",
			"version": "9.9.9",
			"purl": "pkg:generic/tools/counted-lib@9.9.9"
		}
	]
}`

// componentVersionsCounts is the count half of the /components/versions body.
type componentVersionsCounts struct {
	Pagination struct {
		Total int64 `json:"total"`
	} `json:"pagination"`
	VersionCount  int64 `json:"versionCount"`
	ArtifactCount int64 `json:"artifactCount"`
}

// getComponentVersionCounts fetches the page and returns its corpus counts.
func getComponentVersionCounts(t *testing.T, baseURL, query, apiKey string) componentVersionsCounts {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet,
		baseURL+"/api/v1/components/versions?limit=50&"+query, "", apiKey)
	if err != nil {
		t.Fatalf("getting component versions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("getting component versions %q: status %d", query, resp.StatusCode)
	}
	var counts componentVersionsCounts
	if err := json.NewDecoder(resp.Body).Decode(&counts); err != nil {
		t.Fatalf("decoding component versions: %v", err)
	}
	return counts
}

func TestComponentVersionCountsRespectFiltersAndVisibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 8404, "count-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "count-owner", nil)
	is.NoErr(err)

	publicSrc := discoverNS(t, pool, "count-public", ownerID, "public")
	privateSrc := discoverNS(t, pool, "count-private", ownerID, "private")

	// Two public artifacts carrying counted-lib at two different versions, and
	// one private artifact carrying a third version. Every count below is
	// different with the private row in than with it out, which is what makes a
	// dropped visibility filter visible rather than merely suspicious.
	ingestInto(t, srv.URL, publicSrc, fmt.Sprintf(countSBOMTemplate, 1, 1, 1, "1.0.0", "1.0.0"), ownerKey)
	ingestInto(t, srv.URL, publicSrc, fmt.Sprintf(countSBOMTemplate, 2, 2, 2, "2.0.0", "2.0.0"), ownerKey)
	ingestInto(t, srv.URL, privateSrc, fmt.Sprintf(countSBOMTemplate, 3, 3, 3, "3.0.0", "3.0.0"), ownerKey)

	// Anonymous: the private namespace is invisible, so it contributes to none
	// of the three figures. Two rows per public SBOM — the library and the
	// grouped application share the name — hence four.
	anon := getComponentVersionCounts(t, srv.URL, "name=counted-lib", "")
	is.Equal(anon.Pagination.Total, int64(4))
	is.Equal(anon.VersionCount, int64(3)) // 1.0.0, 2.0.0 and the shared 9.9.9
	is.Equal(anon.ArtifactCount, int64(2))

	// The owner sees the private namespace too, so every figure grows.
	owner := getComponentVersionCounts(t, srv.URL, "name=counted-lib", ownerKey)
	is.Equal(owner.Pagination.Total, int64(6))
	is.Equal(owner.VersionCount, int64(4))
	is.Equal(owner.ArtifactCount, int64(3))

	// Each filter narrows the counts, not just the page. These moved into the
	// materialized CTE, so a filter lost there would show up as a count that
	// ignores it while the rows below still obey it.
	group := getComponentVersionCounts(t, srv.URL, "name=counted-lib&group="+url.QueryEscape("tools"), ownerKey)
	is.Equal(group.Pagination.Total, int64(3))
	is.Equal(group.VersionCount, int64(1))
	is.Equal(group.ArtifactCount, int64(3))

	typed := getComponentVersionCounts(t, srv.URL, "name=counted-lib&type=library", ownerKey)
	is.Equal(typed.Pagination.Total, int64(3))
	is.Equal(typed.VersionCount, int64(3))

	version := getComponentVersionCounts(t, srv.URL, "name=counted-lib&version=2.0.0", ownerKey)
	is.Equal(version.Pagination.Total, int64(1))
	is.Equal(version.VersionCount, int64(1))
	is.Equal(version.ArtifactCount, int64(1))
}
