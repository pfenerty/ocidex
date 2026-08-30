package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
)

// Artifact relationship integration tests (ADR-041, ocidex-rj4.2).
//
// These cover the ADR's Confirmation section: both layers of the identity key
// (R1), version drift surfacing rather than blocking a match (R2), versioned
// names staying distinct (R3), and namespace visibility on both directions
// (R5) — including the cross-source resolution that is the reason the namespace
// epic came first.

// relImageSBOM is a container whose SBOM records the ocidex binary at v1.2.1 —
// one version behind the tracked artifact, which is the drift the feature
// exists to surface.
const relImageSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:51000000-0000-0000-0000-000000000001",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "ghcr.io/pfenerty/ocidex-api@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			"version": "v0.9.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-01-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "application",
			"name": "ocidex",
			"version": "v1.2.1",
			"purl": "pkg:golang/github.com/pfenerty/ocidex@v1.2.1"
		}
	]
}`

// relBinarySBOM is the uploaded first-party binary, tracked as an artifact in
// its own right (ADR-040) and therefore eligible to be the other end of a
// relationship (ADR-041 R4).
const relBinarySBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:51000000-0000-0000-0000-000000000002",
	"version": 1,
	"metadata": {
		"component": {
			"type": "application",
			"name": "ocidex",
			"version": "v1.2.3",
			"purl": "pkg:golang/github.com/pfenerty/ocidex@v1.2.3"
		}
	},
	"components": [
		{
			"type": "library",
			"name": "chi",
			"version": "5.0.12",
			"purl": "pkg:golang/github.com/go-chi/chi/v5@5.0.12"
		}
	]
}`

// relTupleImageSBOM carries a purl-less component, so it can only be matched
// through ADR-019 Rule 2's (type, name, group) fallback. It deliberately ships
// libfoo-2 and not libfoo-1: those two names differ only by a numeric suffix,
// which ADR-019 Rule 3 would collapse and ADR-041 R3 forbids collapsing.
const relTupleImageSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:51000000-0000-0000-0000-000000000003",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "ghcr.io/pfenerty/tuple-image@sha256:3333333333333333333333333333333333333333333333333333333333333333",
			"version": "v2.0.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-01-02T00:00:00Z"}
			]
		}
	},
	"components": [
		{"type": "file", "name": "libfoo-2", "version": "2.0.0"}
	]
}`

// relTupleBinarySBOM is a purl-less uploaded subject. Its name is substituted so
// one fixture can seed both libfoo-1 and libfoo-2.
const relTupleBinarySBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:51000000-0000-0000-0000-00000000000%s",
	"version": 1,
	"metadata": {
		"component": {
			"type": "file",
			"name": "%s",
			"version": "%s"
		}
	},
	"components": [
		{"type": "library", "name": "zlib", "version": "1.3.1", "purl": "pkg:generic/zlib@1.3.1"}
	]
}`

// tupleBinary renders relTupleBinarySBOM for one purl-less subject. The serial
// number varies too, since two SBOMs may not share one.
func tupleBinary(serialSuffix, name, version string) string {
	return fmt.Sprintf(relTupleBinarySBOM, serialSuffix, name, version)
}

// relationEntry mirrors service.ArtifactRelation over the wire. Pointer fields
// distinguish "absent" from "empty", which is load-bearing for IsCurrent:
// ADR-041 R2 makes nil mean "cannot tell", not "no drift".
type relationEntry struct {
	ArtifactID     string  `json:"artifactId"`
	ArtifactType   string  `json:"artifactType"`
	ArtifactName   string  `json:"artifactName"`
	SubjectVersion *string `json:"subjectVersion"`
	MatchedVersion *string `json:"matchedVersion"`
	CurrentVersion *string `json:"currentVersion"`
	IsCurrent      *bool   `json:"isCurrent"`
}

// fetchRelations calls one relationship direction and returns its entries.
// direction is "usages" or "contains" — which is also the response body's key.
func fetchRelations(t *testing.T, baseURL, apiKey, artifactID, direction string) []relationEntry {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/artifacts/"+artifactID+"/"+direction, "", apiKey)
	if err != nil {
		t.Fatalf("get %s: %v", direction, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get %s: status %d", direction, resp.StatusCode)
	}
	// Decoded into a struct rather than a map: huma adds a "$schema" string to
	// response bodies, which a map[string][]relationEntry cannot hold.
	var body struct {
		Usages   []relationEntry `json:"usages"`
		Contains []relationEntry `json:"contains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode %s: %v", direction, err)
	}
	if direction == "contains" {
		return body.Contains
	}
	return body.Usages
}

// relationStatus returns just the HTTP status of a relationship request, for the
// cases where the assertion is about visibility rather than content.
func relationStatus(t *testing.T, baseURL, apiKey, artifactID, direction string) int {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/artifacts/"+artifactID+"/"+direction, "", apiKey)
	if err != nil {
		t.Fatalf("get %s: %v", direction, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// ingestOK posts an SBOM and fails with the server's own error body, which is
// the only thing that makes a 422 from the ADR-040 upload validation
// diagnosable.
func ingestOK(t *testing.T, baseURL, apiKey, path, body string) {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodPost, baseURL+path, body, apiKey)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		detail, _ := io.ReadAll(resp.Body)
		t.Fatalf("post %s: status %d: %s", path, resp.StatusCode, detail)
	}
}

// artifactIDByName reads an artifact id straight from the database. The list
// endpoints go through rollups, which these tests do not otherwise need to
// refresh.
func artifactIDByName(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(t.Context(), `SELECT id::text FROM artifact WHERE name = $1`, name).Scan(&id)
	if err != nil {
		t.Fatalf("artifact %q: %v", name, err)
	}
	return id
}

// uploadPath builds the ingest path for a non-container subject, which must
// declare its own identity (ADR-040).
func uploadPath(sourceID, subjectType, subjectName, digest string) string {
	q := url.Values{
		"source":       {sourceID},
		"subject_type": {subjectType},
		"subject_name": {subjectName},
		"digest":       {digest},
	}
	return "/api/v1/sboms?" + q.Encode()
}

// TestArtifactUsagesAndContainsAcrossSources is the headline case: an uploaded
// binary and a scanned image arrive through two different sources in one
// namespace, and the relationship spans them (ADR-041 R5). It also asserts the
// drift semantics of R2 — a version difference is reported, not treated as a
// non-match.
func TestArtifactUsagesAndContainsAcrossSources(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7301, "rel-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", nil)
	is.NoErr(err)

	nsID := seedNamespace(t, pool, "rel-ns", ownerID, "public")
	registrySrc := seedSource(t, pool, nsID, "oci_registry", "ghcr")
	uploadSrc := seedSource(t, pool, nsID, "upload", "ci")

	post := func(path, body string) {
		ingestOK(t, srv.URL, ownerKey, path, body)
	}
	post("/api/v1/sboms?source="+registrySrc, relImageSBOM)
	post(uploadPath(uploadSrc, "application", "ocidex",
		"sha256:2222222222222222222222222222222222222222222222222222222222222222"), relBinarySBOM)

	binaryID := artifactIDByName(t, pool, "ocidex")
	imageID := artifactIDByName(t, pool, "ghcr.io/pfenerty/ocidex-api")

	// usages: "where does this binary ship?" — the image, one version behind.
	usages := fetchRelations(t, srv.URL, ownerKey, binaryID, "usages")
	is.Equal(len(usages), 1)
	is.Equal(usages[0].ArtifactID, imageID)
	is.Equal(usages[0].ArtifactType, "container")
	is.True(usages[0].MatchedVersion != nil)
	is.Equal(*usages[0].MatchedVersion, "v1.2.1")
	is.True(usages[0].CurrentVersion != nil)
	is.Equal(*usages[0].CurrentVersion, "v1.2.3")
	is.True(usages[0].IsCurrent != nil)
	is.Equal(*usages[0].IsCurrent, false)
	// The containing image's own build is reported too, so a caller can say
	// *which* image build carries the stale copy.
	is.True(usages[0].SubjectVersion != nil)
	is.Equal(*usages[0].SubjectVersion, "v0.9.0")

	// contains: the exact inverse.
	contains := fetchRelations(t, srv.URL, ownerKey, imageID, "contains")
	is.Equal(len(contains), 1)
	is.Equal(contains[0].ArtifactID, binaryID)
	is.Equal(contains[0].ArtifactName, "ocidex")
	is.Equal(*contains[0].MatchedVersion, "v1.2.1")
	is.Equal(*contains[0].CurrentVersion, "v1.2.3")
	is.Equal(*contains[0].IsCurrent, false)
}

// TestArtifactRelationsTupleFallbackAndVersionedNames drives the second layer of
// the identity key — components with no purl match on (type, name, group) —
// and pins ADR-041 R3: libfoo-1 and libfoo-2 are two artifacts, and the
// versioned-name post-pass that diff applies must NOT run here.
func TestArtifactRelationsTupleFallbackAndVersionedNames(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7401, "tuple-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", nil)
	is.NoErr(err)

	nsID := seedNamespace(t, pool, "tuple-ns", ownerID, "public")
	registrySrc := seedSource(t, pool, nsID, "oci_registry", "ghcr")
	uploadSrc := seedSource(t, pool, nsID, "upload", "ci")

	post := func(path, body string) {
		ingestOK(t, srv.URL, ownerKey, path, body)
	}
	post("/api/v1/sboms?source="+registrySrc, relTupleImageSBOM)
	post(uploadPath(uploadSrc, "file", "libfoo-1",
		"sha256:4444444444444444444444444444444444444444444444444444444444444444"),
		tupleBinary("4", "libfoo-1", "1.0.0"))
	post(uploadPath(uploadSrc, "file", "libfoo-2",
		"sha256:5555555555555555555555555555555555555555555555555555555555555555"),
		tupleBinary("5", "libfoo-2", "2.0.0"))

	imageID := artifactIDByName(t, pool, "ghcr.io/pfenerty/tuple-image")
	foo1ID := artifactIDByName(t, pool, "libfoo-1")
	foo2ID := artifactIDByName(t, pool, "libfoo-2")

	// R1 layer 2: the purl-less component resolves to the purl-less artifact.
	usages2 := fetchRelations(t, srv.URL, ownerKey, foo2ID, "usages")
	is.Equal(len(usages2), 1)
	is.Equal(usages2[0].ArtifactID, imageID)
	is.Equal(*usages2[0].MatchedVersion, "2.0.0")
	is.Equal(*usages2[0].CurrentVersion, "2.0.0")
	is.Equal(*usages2[0].IsCurrent, true)

	// R3: libfoo-1 is not in this image, and no numeric-suffix collapsing may
	// pretend otherwise.
	is.Equal(len(fetchRelations(t, srv.URL, ownerKey, foo1ID, "usages")), 0)

	contains := fetchRelations(t, srv.URL, ownerKey, imageID, "contains")
	is.Equal(len(contains), 1)
	is.Equal(contains[0].ArtifactID, foo2ID)
}

// TestArtifactRelationsRespectNamespaceVisibility checks that neither direction
// leaks across the tenancy boundary (ADR-041 R5): a viewer who can see the
// binary but not the image that ships it must see no relationship at all,
// rather than a redacted one.
func TestArtifactRelationsRespectNamespaceVisibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7501, "vis-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", nil)
	is.NoErr(err)
	strangerID := seedUser(t, pool, 7502, "vis-stranger", "member")
	strangerKey, err := authSvc.CreateAPIKey(t.Context(), strangerID, "stranger", nil)
	is.NoErr(err)

	publicNS := seedNamespace(t, pool, "vis-public", ownerID, "public")
	privateNS := seedNamespace(t, pool, "vis-private", ownerID, "private")
	uploadSrc := seedSource(t, pool, publicNS, "upload", "ci")
	registrySrc := seedSource(t, pool, privateNS, "oci_registry", "ghcr")

	post := func(path, body string) {
		ingestOK(t, srv.URL, ownerKey, path, body)
	}
	post(uploadPath(uploadSrc, "application", "ocidex",
		"sha256:6666666666666666666666666666666666666666666666666666666666666666"), relBinarySBOM)
	post("/api/v1/sboms?source="+registrySrc, relImageSBOM)

	binaryID := artifactIDByName(t, pool, "ocidex")
	imageID := artifactIDByName(t, pool, "ghcr.io/pfenerty/ocidex-api")

	// The owner sees the relationship spanning both namespaces.
	is.Equal(len(fetchRelations(t, srv.URL, ownerKey, binaryID, "usages")), 1)

	// The stranger can read the public binary, but the image that ships it is in
	// a namespace they cannot see — so the usage is absent, not redacted.
	is.Equal(len(fetchRelations(t, srv.URL, strangerKey, binaryID, "usages")), 0)

	// Asking about the private image itself is a 404 either way: the visibility
	// check runs before the relationship query, so a caller cannot probe for the
	// existence of artifacts they cannot see.
	is.Equal(relationStatus(t, srv.URL, strangerKey, imageID, "contains"), http.StatusNotFound)
	is.Equal(relationStatus(t, srv.URL, strangerKey, imageID, "usages"), http.StatusNotFound)

	// Flipping the namespace public makes the same relationship appear, with no
	// re-ingest: relationships are derived, never stored (ADR-041).
	_, err = pool.Exec(t.Context(), `UPDATE namespace SET visibility = 'public' WHERE id = $1`, privateNS)
	is.NoErr(err)
	is.Equal(len(fetchRelations(t, srv.URL, strangerKey, binaryID, "usages")), 1)
	is.Equal(len(fetchRelations(t, srv.URL, strangerKey, imageID, "contains")), 1)
}
