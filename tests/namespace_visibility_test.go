package tests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
)

// alpineSBOM is a second container subject, distinct from minimalSBOM's
// docker.io/ubuntu, so a test can place two artifacts in one namespace.
const alpineSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:44444444-4444-4444-4444-444444444444",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/alpine@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			"version": "3.20",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-03-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "musl",
			"version": "1.2.5",
			"purl": "pkg:apk/alpine/musl@1.2.5?arch=x86_64&distro=alpine-3.20"
		}
	]
}`

// seedNamespace inserts a namespace owned by ownerID.
func seedNamespace(t *testing.T, pool *pgxpool.Pool, name string, ownerID pgtype.UUID, visibility string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(t.Context(), `
		INSERT INTO namespace (name, owner_id, visibility)
		VALUES ($1, $2, $3)
		RETURNING id::text
	`, name, ownerID, visibility).Scan(&id)
	if err != nil {
		t.Fatalf("seed namespace %q: %v", name, err)
	}
	return id
}

// seedSource inserts a source inside a namespace.
func seedSource(t *testing.T, pool *pgxpool.Pool, namespaceID, kind, name string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(t.Context(), `
		INSERT INTO source (namespace_id, kind, name)
		VALUES ($1, $2, $3)
		RETURNING id::text
	`, namespaceID, kind, name).Scan(&id)
	if err != nil {
		t.Fatalf("seed source %q: %v", name, err)
	}
	return id
}

// placeSBOM moves an already-ingested SBOM into a namespace via a source, and
// links its artifact to the same namespace.
//
// Ingest does not yet bind an uploaded SBOM to a source — that lands with the
// non-container upload path — so the placement the API will eventually do is
// done here directly. What is under test is the visibility rule downstream of
// it, which is where ADR-039 actually changed behaviour.
func placeSBOM(t *testing.T, pool *pgxpool.Pool, sbomID, namespaceID, sourceID string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
		WITH upd AS (
			UPDATE sbom SET namespace_id = $2, source_id = $3
			WHERE id = $1
			RETURNING artifact_id
		)
		INSERT INTO artifact_namespace (artifact_id, namespace_id)
		SELECT artifact_id, $2 FROM upd
		ON CONFLICT DO NOTHING
	`, sbomID, namespaceID, sourceID); err != nil {
		t.Fatalf("place sbom %s: %v", sbomID, err)
	}
}

// artifactNames lists the artifact names the given API key can see.
func artifactNames(t *testing.T, baseURL, apiKey string) []string {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/artifacts?sufficient=false", "", apiKey)
	if err != nil {
		t.Fatalf("list artifacts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list artifacts: status %d", resp.StatusCode)
	}
	var body struct {
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode artifacts: %v", err)
	}
	names := make([]string, 0, len(body.Data))
	for _, a := range body.Data {
		names = append(names, a.Name)
	}
	return names
}

// componentCount reports how many rollup rows for a named component the key can
// see. This is the read path that goes through visible_namespace_ids, so it is
// the set-returning half of the visibility rule.
func componentCount(t *testing.T, baseURL, apiKey, name string) int {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/components?name="+name, "", apiKey)
	if err != nil {
		t.Fatalf("list components: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list components: status %d", resp.StatusCode)
	}
	var body struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode components: %v", err)
	}
	return len(body.Data)
}

// TestPrivateNamespaceHidesSBOMsFromNonOwner is the ADR-039 restatement of the
// pre-existing private-registry rule: ownership and visibility now live on
// namespace, and both the per-row (artifact_visible) and set-returning
// (visible_namespace_ids) forms must agree on it.
func TestPrivateNamespaceHidesSBOMsFromNonOwner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7101, "ns-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", "read-write")
	is.NoErr(err)
	strangerID := seedUser(t, pool, 7102, "ns-stranger", "member")
	strangerKey, err := authSvc.CreateAPIKey(t.Context(), strangerID, "stranger", "read-write")
	is.NoErr(err)

	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", minimalSBOM, ownerKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingested map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingested))
	resp.Body.Close()

	nsID := seedNamespace(t, pool, "private-ns", ownerID, "private")
	srcID := seedSource(t, pool, nsID, "upload", "ci")
	placeSBOM(t, pool, ingested["id"].(string), nsID, srcID)
	refreshRollups(t, pool)

	is.Equal(artifactNames(t, srv.URL, ownerKey), []string{"docker.io/ubuntu"})
	is.Equal(len(artifactNames(t, srv.URL, strangerKey)), 0)
	is.Equal(len(artifactNames(t, srv.URL, "")), 0)

	is.True(componentCount(t, srv.URL, ownerKey, "adduser") > 0)
	is.Equal(componentCount(t, srv.URL, strangerKey, "adduser"), 0)

	// Flipping the namespace public exposes it to everyone — visibility is read
	// from namespace, not cached anywhere downstream.
	_, err = pool.Exec(t.Context(), `UPDATE namespace SET visibility = 'public' WHERE id = $1`, nsID)
	is.NoErr(err)
	is.Equal(artifactNames(t, srv.URL, strangerKey), []string{"docker.io/ubuntu"})
}

// TestSourcesInOneNamespaceShareVisibility is the property the split exists
// for: two ingest channels under one namespace are one tenancy boundary, so a
// viewer sees both or neither regardless of which source an SBOM arrived
// through.
func TestSourcesInOneNamespaceShareVisibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7201, "shared-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", "read-write")
	is.NoErr(err)
	strangerID := seedUser(t, pool, 7202, "shared-stranger", "member")
	strangerKey, err := authSvc.CreateAPIKey(t.Context(), strangerID, "stranger", "read-write")
	is.NoErr(err)

	ingest := func(body string) string {
		t.Helper()
		resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", body, ownerKey)
		is.NoErr(err)
		is.Equal(resp.StatusCode, http.StatusCreated)
		var out map[string]any
		is.NoErr(json.NewDecoder(resp.Body).Decode(&out))
		resp.Body.Close()
		return out["id"].(string)
	}
	fromRegistry := ingest(minimalSBOM)
	fromUpload := ingest(alpineSBOM)

	nsID := seedNamespace(t, pool, "shared-ns", ownerID, "private")
	registrySrc := seedSource(t, pool, nsID, "oci_registry", "ghcr")
	uploadSrc := seedSource(t, pool, nsID, "upload", "ci")
	placeSBOM(t, pool, fromRegistry, nsID, registrySrc)
	placeSBOM(t, pool, fromUpload, nsID, uploadSrc)
	refreshRollups(t, pool)

	is.Equal(len(artifactNames(t, srv.URL, ownerKey)), 2)
	is.Equal(len(artifactNames(t, srv.URL, strangerKey)), 0)

	_, err = pool.Exec(t.Context(), `UPDATE namespace SET visibility = 'public' WHERE id = $1`, nsID)
	is.NoErr(err)
	is.Equal(len(artifactNames(t, srv.URL, strangerKey)), 2)
}
