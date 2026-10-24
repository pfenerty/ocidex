package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/matryer/is"
)

// licensedSBOMTemplate is a container SBOM with one MIT-licensed library at a
// given version: serial and digest suffix, image name, library version.
const licensedSBOMTemplate = `{
	"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
	"serialNumber": "urn:uuid:1ce00000-0000-0000-0000-%012d",
	"metadata": {"component": {
		"type": "container", "name": "registry.test/%s@sha256:%064d", "version": "1.0.0",
		"properties": [
			{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
			{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-01-01T00:00:00Z"}
		]
	}},
	"components": [{
		"type": "library", "name": "licensed-lib", "version": "%s",
		"purl": "pkg:generic/licensed-lib@%s",
		"licenses": [{"license": {"id": "MIT"}}]
	}]
}`

type licenseComponentsPage struct {
	Data []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"data"`
	Pagination struct {
		Total int `json:"total"`
	} `json:"pagination"`
}

func getLicenseComponents(t *testing.T, baseURL, licenseID, apiKey, query string) licenseComponentsPage {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/licenses/"+licenseID+"/components"+query, "", apiKey)
	if err != nil {
		t.Fatalf("listing license components: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing license components: status %d: %s", resp.StatusCode, body)
	}
	var page licenseComponentsPage
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decoding license components: %v", err)
	}
	return page
}

// TestLicenseComponentsFromRollup covers ocidex-zbe5: the route reads
// license_component_rollup, lists each distinct component once however many
// SBOMs and visible namespaces carry it, hides components only a private
// namespace holds, orders newest version first, and totals before paging.
func TestLicenseComponentsFromRollup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	is := is.New(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	owner := seedUser(t, pool, 9301, "license-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), owner, "license-owner", nil)
	is.NoErr(err)
	outsider := seedUser(t, pool, 9302, "license-outsider", "member")
	outsiderKey, err := authSvc.CreateAPIKey(t.Context(), outsider, "license-outsider", nil)
	is.NoErr(err)
	public := discoverNS(t, pool, "lic-public", owner, "public")
	private := discoverNS(t, pool, "lic-private", owner, "private")

	ingest := func(src string, n int, image, version string) {
		ingestInto(t, srv.URL, src, fmt.Sprintf(licensedSBOMTemplate, n, image, n, version, version), ownerKey)
	}
	ingest(public, 1, "app-a", "1.2.0")
	ingest(public, 2, "app-b", "1.2.0")  // same component, another SBOM
	ingest(private, 3, "app-c", "1.2.0") // same component, another namespace
	ingest(public, 4, "app-a", "1.10.0")
	ingest(private, 5, "app-c", "2.0.0") // only in the private namespace
	refreshRollups(t, pool)

	var licenseID string
	is.NoErr(pool.QueryRow(t.Context(), `SELECT id::text FROM license WHERE spdx_id = 'MIT'`).Scan(&licenseID))

	page := getLicenseComponents(t, srv.URL, licenseID, ownerKey, "")
	is.Equal(page.Pagination.Total, 3)
	is.Equal(len(page.Data), 3)
	is.Equal(page.Data[0].Version, "2.0.0")
	is.Equal(page.Data[1].Version, "1.10.0")
	is.Equal(page.Data[2].Version, "1.2.0")

	page = getLicenseComponents(t, srv.URL, licenseID, outsiderKey, "")
	is.Equal(page.Pagination.Total, 2) // 2.0.0 is only in the private namespace

	page = getLicenseComponents(t, srv.URL, licenseID, ownerKey, "?limit=1&offset=1")
	is.Equal(page.Pagination.Total, 3)
	is.Equal(len(page.Data), 1)
	is.Equal(page.Data[0].Version, "1.10.0")
}
