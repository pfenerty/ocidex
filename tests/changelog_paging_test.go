package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/matryer/is"
)

// Changelog pagination (ocidex-7gf7.4).
//
// The changelog used to diff every consecutive pair of versions in one response
// and the frontend rendered all of them, so an artifact with a thousand versions
// timed out. These tests pin the window: a page holds at most `limit` entries,
// pages are contiguous and newest-first, and the total is the number of
// consecutive-version pairs — a figure the server knows without diffing
// anything, which is what makes it cheap.

// changelogSBOMTemplate is one version of a container artifact. Consecutive
// versions differ by one package so every pair produces a non-empty diff, and
// the last two are identical so the zero-change pair is covered too.
const changelogSBOMTemplate = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:33333333-3333-3333-3333-3333333333%02d",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/changelog-paging-fixture@sha256:%064d",
			"version": "v1.%d.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-04-%02dT00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "pkg-%d",
			"version": "1.0.0",
			"purl": "pkg:generic/pkg-%d@1.0.0"
		}
	]
}`

// changelogVersions is the number of versions seeded; one fewer than this is
// the number of entries the full changelog holds.
const changelogVersions = 8

// changelogEntry is the shape of a changelog entry this test reads.
type changelogEntry struct {
	From struct {
		SubjectVersion string `json:"subjectVersion"`
	} `json:"from"`
	To struct {
		SubjectVersion string `json:"subjectVersion"`
	} `json:"to"`
}

// changelogPage is one page of the changelog endpoint.
type changelogPage struct {
	Entries    []changelogEntry `json:"entries"`
	Pagination struct {
		Total  int64 `json:"total"`
		Limit  int32 `json:"limit"`
		Offset int32 `json:"offset"`
	} `json:"pagination"`
}

// getChangelog fetches one page.
func getChangelog(t *testing.T, baseURL, artifactID, query, apiKey string) changelogPage {
	t.Helper()
	url := baseURL + "/api/v1/artifacts/" + artifactID + "/changelog?arch=amd64"
	if query != "" {
		url += "&" + query
	}
	resp, err := doWithAuth(t, http.MethodGet, url, "", apiKey)
	if err != nil {
		t.Fatalf("getting changelog: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("getting changelog %q: status %d", query, resp.StatusCode)
	}
	var page changelogPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decoding changelog: %v", err)
	}
	return page
}

func TestArtifactChangelogPaging(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	memberID := seedUser(t, pool, 8402, "changelog-paging-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "changelog-paging", nil)
	is.NoErr(err)
	path := ingestPath(t, pool, memberID)

	// Versions v1.1.0 .. v1.8.0. The last two carry the same package so their
	// diff is empty: a pair the old code dropped from the response entirely,
	// and which now has to be present for the page arithmetic to hold.
	var artifactID string
	for v := 1; v <= changelogVersions; v++ {
		pkg := v
		if v == changelogVersions {
			pkg = v - 1
		}
		sbom := fmt.Sprintf(changelogSBOMTemplate, v, v, v, v, pkg, pkg)
		artifactID = mustIngest(t, srv.URL, path, sbom, memberKey)
	}

	// mustIngest returns the SBOM id, not the artifact id; read the artifact
	// off the SBOM.
	if err := pool.QueryRow(t.Context(),
		`SELECT artifact_id::text FROM sbom WHERE id = $1`, artifactID).Scan(&artifactID); err != nil {
		t.Fatalf("resolving artifact id: %v", err)
	}

	pairs := int64(changelogVersions - 1)

	// The default page is bounded even though the caller asked for nothing.
	// This is the assertion that would have caught the original bug: it does
	// not depend on how fast the machine is.
	def := getChangelog(t, srv.URL, artifactID, "", memberKey)
	is.Equal(def.Pagination.Total, pairs)
	is.Equal(def.Pagination.Limit, int32(20))
	if len(def.Entries) > int(def.Pagination.Limit) {
		t.Fatalf("default page holds %d entries, over its own limit of %d",
			len(def.Entries), def.Pagination.Limit)
	}
	is.Equal(len(def.Entries), int(pairs))

	// Entries are newest-first, so the first entry of the first page is the
	// newest pair.
	is.Equal(def.Entries[0].To.SubjectVersion, "v1.8.0")
	is.Equal(def.Entries[0].From.SubjectVersion, "v1.7.0")

	// A page holds exactly its limit while entries remain — including the
	// v1.7.0 -> v1.8.0 pair, whose diff is empty. Suppressing it would make the
	// count unknowable without diffing every pair, which is the unbounded work
	// the window removes.
	first := getChangelog(t, srv.URL, artifactID, "limit=3", memberKey)
	is.Equal(len(first.Entries), 3)
	is.Equal(first.Pagination.Total, pairs)

	// The next page continues where the first stopped, with no gap and no
	// repeat: page 2's newest entry is the pair immediately older than page 1's
	// oldest.
	second := getChangelog(t, srv.URL, artifactID, "limit=3&offset=3", memberKey)
	is.Equal(len(second.Entries), 3)
	is.Equal(second.Entries[0].To.SubjectVersion, first.Entries[2].From.SubjectVersion)

	// The last page is short because the entries ran out, not because the limit
	// changed: 7 pairs, 3 per page.
	last := getChangelog(t, srv.URL, artifactID, "limit=3&offset=6", memberKey)
	is.Equal(len(last.Entries), 1)
	is.Equal(last.Entries[0].From.SubjectVersion, "v1.1.0")
	is.Equal(last.Entries[0].To.SubjectVersion, "v1.2.0")

	// Past the end is an empty page, not an error and not a wrap to the start.
	past := getChangelog(t, srv.URL, artifactID, "limit=3&offset=99", memberKey)
	is.Equal(len(past.Entries), 0)
	is.Equal(past.Pagination.Total, pairs)
}
