package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/matryer/is"
)

// keysetSBOM builds a minimal container SBOM JSON for the given artifact name,
// digest, and version, with the named components.
func keysetSBOM(name, digest, version string, components []string) string {
	var comps strings.Builder
	for i, c := range components {
		if i > 0 {
			comps.WriteString(",")
		}
		fmt.Fprintf(&comps, `{"type":"library","name":%q,"version":"1.0.0","purl":"pkg:generic/%s@1.0.0"}`, c, c)
	}
	return fmt.Sprintf(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"version": 1,
		"metadata": {
			"component": {
				"type": "container",
				"name": "%s@%s",
				"version": "%s",
				"properties": [
					{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
					{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-01-01T00:00:00Z"}
				]
			}
		},
		"components": [%s]
	}`, name, digest, version, comps.String())
}

// pageAll walks a cursor-paginated endpoint, following nextCursor until
// exhausted, and returns the concatenated id list. dataKey is "data" or
// "components". idField is the JSON field holding each row's id.
func pageAll(t *testing.T, srv, path, dataKey string) []string {
	t.Helper()
	is := is.New(t)
	var ids []string
	cursor := ""
	for i := 0; i < 100; i++ { // guard against infinite loop
		u := path + "&limit=2"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		resp, err := doGet(t, srv+u)
		is.NoErr(err)
		is.Equal(resp.StatusCode, http.StatusOK)
		var body map[string]any
		is.NoErr(json.NewDecoder(resp.Body).Decode(&body))
		resp.Body.Close()

		rows, _ := body[dataKey].([]any)
		for _, r := range rows {
			ids = append(ids, r.(map[string]any)["id"].(string))
		}
		pg := body["pagination"].(map[string]any)
		if hasMore, _ := pg["hasMore"].(bool); !hasMore {
			break
		}
		cursor = pg["nextCursor"].(string)
	}
	return ids
}

// assertUnique fails if the id slice contains duplicates (a keyset gap/overlap bug).
func assertUnique(t *testing.T, ids []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate id across pages: %s (ids=%v)", id, ids)
		}
		seen[id] = true
	}
}

// TestKeysetPagination_NoGapsOrDupes verifies the three keyset-paginated
// endpoints page cleanly through results smaller than the row count.
func TestKeysetPagination_NoGapsOrDupes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	memberID := seedUser(t, pool, 7401, "keyset-member", "member")
	key, err := authSvc.CreateAPIKey(t.Context(), memberID, "keyset-test", "read-write")
	is.NoErr(err)

	ingest := func(body string) string {
		resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", body, key)
		is.NoErr(err)
		is.Equal(resp.StatusCode, http.StatusCreated)
		var r map[string]any
		is.NoErr(json.NewDecoder(resp.Body).Decode(&r))
		resp.Body.Close()
		return r["id"].(string)
	}

	// 5 components → /sboms/{id}/components keyset.
	sbomID := ingest(keysetSBOM("docker.io/multi", "sha256:"+strings.Repeat("a", 64), "1.0.0",
		[]string{"zlib", "openssl", "busybox", "curl", "bash"}))

	// 3 distinct artifacts → /artifacts keyset.
	ingest(keysetSBOM("docker.io/alpine", "sha256:"+strings.Repeat("b", 64), "3.18", []string{"musl"}))
	ingest(keysetSBOM("docker.io/debian", "sha256:"+strings.Repeat("c", 64), "12", []string{"glibc"}))
	// 3 SBOMs under the same artifact (docker.io/multi) → /artifacts/{id}/sboms keyset.
	ingest(keysetSBOM("docker.io/multi", "sha256:"+strings.Repeat("d", 64), "1.1.0", []string{"zlib"}))
	ingest(keysetSBOM("docker.io/multi", "sha256:"+strings.Repeat("e", 64), "1.2.0", []string{"zlib"}))

	// --- /sboms/{id}/components: 5 rows, page size 2 ---
	compIDs := pageAll(t, srv.URL, fmt.Sprintf("/api/v1/sboms/%s/components?", sbomID), "components")
	is.Equal(len(compIDs), 5)
	assertUnique(t, compIDs)

	// --- /artifacts: 3 rows, page size 2 ---
	artIDs := pageAll(t, srv.URL, "/api/v1/artifacts?sufficient=false&", "data")
	is.Equal(len(artIDs), 3)
	assertUnique(t, artIDs)

	// Find the multi artifact id.
	resp, err := doGet(t, srv.URL+"/api/v1/artifacts?sufficient=false&limit=200")
	is.NoErr(err)
	var alist map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&alist))
	resp.Body.Close()
	var multiID string
	for _, a := range alist["data"].([]any) {
		am := a.(map[string]any)
		if am["name"] == "docker.io/multi" {
			multiID = am["id"].(string)
		}
	}
	is.True(multiID != "")

	// --- /artifacts/{id}/sboms: 3 rows, page size 2 ---
	sbomIDs := pageAll(t, srv.URL, fmt.Sprintf("/api/v1/artifacts/%s/sboms?", multiID), "data")
	is.Equal(len(sbomIDs), 3)
	assertUnique(t, sbomIDs)
}
