package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/matryer/is"
)

// Offset pagination over a tied ordering (ocidex-kf1p.2).
//
// /components/versions ordered by version parts and the SBOM's created_at, and
// /components by version parts alone. Neither is unique: every component of one
// SBOM shares created_at, and every version that does not parse is all-NULL.
// Postgres returns tied rows in whatever order the plan produces, which can
// differ between the two queries behind page 1 and page 2, so paging repeated
// some rows and never showed others — "the component is missing versions".
//
// One SBOM whose same-named components all carry unparseable versions ties
// every row on every key the queries used to sort by, which is the worst case.

const tiedComponentCount = 9

// tiedSBOM builds a container SBOM with tiedComponentCount components named
// tied-lib, each with a non-semver version so its version parts are NULL.
func tiedSBOM() string {
	comps := make([]string, 0, tiedComponentCount)
	for i := range tiedComponentCount {
		comps = append(comps, fmt.Sprintf(`{
			"type": "library",
			"bom-ref": "tied-%[1]d",
			"name": "tied-lib",
			"version": "build-%[1]d",
			"purl": "pkg:generic/tied-lib@build-%[1]d"
		}`, i))
	}
	return `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:99999999-9999-9999-9999-999999999901",
		"version": 1,
		"metadata": {
			"component": {
				"type": "container",
				"name": "docker.io/tied-fixture@sha256:` + strings.Repeat("9", 64) + `",
				"version": "v1.0.0",
				"properties": [
					{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
					{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-06-01T00:00:00Z"}
				]
			}
		},
		"components": [` + strings.Join(comps, ",") + `]
	}`
}

// collectPagedIDs walks an offset-paginated endpoint with a small page size and
// returns every id it saw, in order, duplicates included. itemsKey names the
// array in the response body.
func collectPagedIDs(t *testing.T, baseURL, path, itemsKey string) []string {
	t.Helper()
	const limit = 2
	var ids []string
	for offset := 0; offset < 10*tiedComponentCount; offset += limit {
		resp, err := doWithAuth(t, http.MethodGet,
			fmt.Sprintf("%s%s&limit=%d&offset=%d", baseURL, path, limit, offset), "", "")
		if err != nil {
			t.Fatalf("getting %s: %v", path, err)
		}
		var body map[string]json.RawMessage
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || err != nil {
			t.Fatalf("getting %s offset %d: status %d, decode err %v", path, offset, resp.StatusCode, err)
		}
		var items []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body[itemsKey], &items); err != nil {
			t.Fatalf("decoding %s items: %v", path, err)
		}
		if len(items) == 0 {
			break
		}
		for _, it := range items {
			ids = append(ids, it.ID)
		}
	}
	return ids
}

func TestOffsetPaginationReturnsEveryTiedRowOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 8405, "tied-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "tied-owner", nil)
	is.NoErr(err)
	src := discoverNS(t, pool, "tied-public", ownerID, "public")
	ingestInto(t, srv.URL, src, tiedSBOM(), ownerKey)

	for _, tc := range []struct{ path, itemsKey string }{
		{"/api/v1/components/versions?name=tied-lib", "versions"},
		{"/api/v1/components?name=tied-lib", "data"},
	} {
		ids := collectPagedIDs(t, srv.URL, tc.path, tc.itemsKey)
		seen := make(map[string]bool, len(ids))
		for _, id := range ids {
			if seen[id] {
				t.Errorf("%s: id %s appeared on more than one page", tc.path, id)
			}
			seen[id] = true
		}
		if len(seen) != tiedComponentCount {
			t.Errorf("%s: paging returned %d distinct rows, want %d", tc.path, len(seen), tiedComponentCount)
		}
	}
}
