package tests

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/matryer/is"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	natsc "github.com/testcontainers/testcontainers-go/modules/nats"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/pfenerty/ocidex/db"
	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/enrichment/provenance"
	"github.com/pfenerty/ocidex/internal/repository"

	"github.com/jackc/pgx/v5/pgtype"
)

// Integration tests run against either a throwaway testcontainers-managed server
// (the local default) or a long-lived server shared by the whole package. CI takes
// the second path: the Tekton go-integration-test task runs plain postgres and nats
// sidecars in the same pod and points these vars at localhost, so no Docker daemon
// is needed inside the build container.
//
// Every test in this package is sequential (no t.Parallel), so isolation on a
// shared server is just "own database per test, dropped on cleanup".
const (
	envPostgresURL = "TEST_POSTGRES_URL"
	envNATSURL     = "TEST_NATS_URL"
)

// requireTestInfra skips the test when there is no way to obtain Postgres.
//
// With TEST_POSTGRES_URL set there is deliberately no escape hatch: an unreachable
// server must fail the test rather than silently skip it. Silent skipping is the
// exact failure this suite is being wired into CI to prevent.
func requireTestInfra(t *testing.T) {
	t.Helper()
	if os.Getenv(envPostgresURL) != "" {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skipf("neither %s nor docker available, skipping integration test", envPostgresURL)
	}
}

// newTestDB provisions an empty database and returns its connection string (as a
// superuser) plus a teardown func. Migrations are NOT run — see setupTestDB.
func newTestDB(t *testing.T) (string, func()) {
	t.Helper()
	if adminURL := os.Getenv(envPostgresURL); adminURL != "" {
		return newSharedTestDB(t, adminURL)
	}
	return newContainerTestDB(t)
}

// newSharedTestDB carves a uniquely-named database out of an already-running server.
func newSharedTestDB(t *testing.T, adminURL string) (string, func()) {
	t.Helper()

	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generating database suffix: %v", err)
	}
	name := "ocidex_test_" + hex.EncodeToString(buf)

	admin, err := pgxpool.New(t.Context(), adminURL)
	if err != nil {
		t.Fatalf("connecting to %s: %v", envPostgresURL, err)
	}
	// pgxpool connects lazily; force a round trip so an unreachable sidecar fails
	// here with a clear message instead of somewhere deep in the test.
	if _, err := admin.Exec(t.Context(), `CREATE DATABASE `+pq(name)); err != nil {
		admin.Close()
		t.Fatalf("creating test database %s: %v", name, err)
	}

	cleanup := func() {
		// Background context: t.Context() is already cancelled by the time
		// t.Cleanup funcs run.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// WITH (FORCE) terminates leftover backends (pg13+) so a pool that outlives
		// its test cannot wedge the drop.
		if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+pq(name)+` WITH (FORCE)`); err != nil {
			t.Logf("dropping test database %s: %v", name, err)
		}
		admin.Close()
	}

	return withDatabase(t, adminURL, name), cleanup
}

// newContainerTestDB starts a throwaway Postgres via testcontainers (local default).
func newContainerTestDB(t *testing.T) (string, func()) {
	t.Helper()
	ctx := t.Context()

	pgContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("ocidex_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("starting postgres container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("getting connection string: %v", err)
	}

	return connStr, func() {
		_ = pgContainer.Terminate(context.Background())
	}
}

// pq quotes a SQL identifier. Names here are generated, but DDL takes no
// placeholders so the quoting has to be explicit.
func pq(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

// withDatabase rewrites a connection URL to point at a different database.
func withDatabase(t *testing.T, raw, dbname string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %s: %v", envPostgresURL, err)
	}
	u.Path = "/" + dbname
	return u.String()
}

// withUser rewrites a connection URL to authenticate as a different role.
func withUser(t *testing.T, raw, user, password string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing connection string: %v", err)
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

// migrateDB applies all goose migrations to the database at connStr.
func migrateDB(t *testing.T, connStr string) {
	t.Helper()
	sqlDB, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("opening migration connection: %v", err)
	}
	defer sqlDB.Close()

	goose.SetBaseFS(db.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("setting dialect: %v", err)
	}
	if err := goose.Up(sqlDB, "migrations"); err != nil {
		t.Fatalf("running migrations: %v", err)
	}
}

// setupTestDB provisions a database, runs migrations, and returns a pool + cleanup func.
func setupTestDB(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()

	connStr, dropDB := newTestDB(t)
	migrateDB(t, connStr)

	pool, err := pgxpool.New(t.Context(), connStr)
	if err != nil {
		dropDB()
		t.Fatalf("creating pool: %v", err)
	}

	return pool, func() {
		pool.Close()
		dropDB()
	}
}

// setupNATS returns a NATS URL: the shared server when TEST_NATS_URL is set,
// otherwise a throwaway container.
func setupNATS(t *testing.T) string {
	t.Helper()
	if url := os.Getenv(envNATSURL); url != "" {
		return url
	}

	ctx := t.Context()
	natsContainer, err := natsc.Run(ctx, "docker.io/nats:latest")
	if err != nil {
		t.Fatalf("start nats container: %v", err)
	}
	t.Cleanup(func() { _ = natsContainer.Terminate(context.Background()) })

	natsURL, err := natsContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("nats connection string: %v", err)
	}
	return natsURL
}

// dropRoleOnCleanup removes a cluster-scoped role at test end. Roles outlive the
// per-test database, so on a shared server a leftover role would make the next run's
// CREATE ROLE fail. No-op with a throwaway container — the whole server goes away.
//
// Register this BEFORE the database teardown so it runs after it (cleanups are
// LIFO): dropping the database first removes the objects the role owns.
func dropRoleOnCleanup(t *testing.T, role string) {
	t.Helper()
	adminURL := os.Getenv(envPostgresURL)
	if adminURL == "" {
		return
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		admin, err := pgxpool.New(ctx, adminURL)
		if err != nil {
			t.Logf("connecting to drop role %s: %v", role, err)
			return
		}
		defer admin.Close()
		if _, err := admin.Exec(ctx, `DROP ROLE IF EXISTS `+pq(role)); err != nil {
			t.Logf("dropping role %s: %v", role, err)
		}
	})
}

// cleanupStream deletes a JetStream stream (and its consumers) when the test ends.
// Only load-bearing on a shared server, where the stream would otherwise leak
// messages and durable consumers into the next test.
func cleanupStream(t *testing.T, js jetstream.JetStream, name string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := js.DeleteStream(ctx, name); err != nil {
			t.Logf("deleting stream %s: %v", name, err)
		}
	})
}

const minimalSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"version": "24.04",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-01-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "adduser",
			"version": "3.118ubuntu2",
			"purl": "pkg:deb/ubuntu/adduser@3.118ubuntu2?arch=all&distro=ubuntu-24.04"
		},
		{
			"type": "library",
			"name": "apt",
			"version": "2.7.14",
			"purl": "pkg:deb/ubuntu/apt@2.7.14?arch=arm64&distro=ubuntu-24.04"
		}
	]
}`

const secondSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/ubuntu@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"version": "24.04.1",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-02-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "adduser",
			"version": "3.118ubuntu5",
			"purl": "pkg:deb/ubuntu/adduser@3.118ubuntu5?arch=all&distro=ubuntu-24.04"
		},
		{
			"type": "library",
			"name": "curl",
			"version": "8.5.0",
			"purl": "pkg:deb/ubuntu/curl@8.5.0?arch=arm64&distro=ubuntu-24.04"
		}
	]
}`

// duplicatePurlSBOM has two components with the same purl — used to verify
// vuln summary queries deduplicate before counting.
const duplicatePurlSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/ubuntu@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"version": "24.04",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-03-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "adduser",
			"version": "3.118ubuntu2",
			"purl": "pkg:deb/ubuntu/adduser@3.118ubuntu2?arch=all&distro=ubuntu-24.04"
		},
		{
			"type": "library",
			"name": "adduser-alias",
			"version": "3.118ubuntu2",
			"purl": "pkg:deb/ubuntu/adduser@3.118ubuntu2?arch=all&distro=ubuntu-24.04"
		}
	]
}`

func TestFullLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	// SBOM ingest + delete require member/owner role; seed user + API key.
	memberID := seedUser(t, pool, 7001, "lifecycle-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "lifecycle-test", "read-write")
	is.NoErr(err)

	// --- Ingest first SBOM ---
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+ingestPath(t, pool, memberID), minimalSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)

	var ingestResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingestResp))
	resp.Body.Close()
	sbomID1 := ingestResp["id"].(string)
	is.True(sbomID1 != "")
	is.Equal(ingestResp["componentCount"], float64(2))

	// --- Verify artifact was created ---
	resp, err = doGet(t, srv.URL+"/api/v1/artifacts?sufficient=false")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)

	var artifactsResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&artifactsResp))
	resp.Body.Close()

	data := artifactsResp["data"].([]any)
	is.Equal(len(data), 1)
	artifact := data[0].(map[string]any)
	is.Equal(artifact["name"], "docker.io/ubuntu")
	is.Equal(artifact["type"], "container")
	artifactID := artifact["id"].(string)

	// --- Verify SBOM is linked to artifact ---
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/artifacts/%s/sboms", srv.URL, artifactID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)

	var sbomsResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&sbomsResp))
	resp.Body.Close()

	sbomData := sbomsResp["data"].([]any)
	is.Equal(len(sbomData), 1)
	sbom := sbomData[0].(map[string]any)
	is.Equal(sbom["subjectVersion"], "24.04")

	// --- Verify components searchable ---
	// The component list reads component_rollup, which a background refresher
	// rebuilds; in the server it lags ingest by up to a poll interval. Drive one
	// pass explicitly rather than sleeping for it.
	refreshRollups(t, pool)

	resp, err = doGet(t, srv.URL+"/api/v1/components?name=adduser")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)

	var compResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&compResp))
	resp.Body.Close()

	compData := compResp["data"].([]any)
	is.True(len(compData) >= 1)

	// --- Ingest second SBOM (same artifact, different components) ---
	// Small delay so created_at differs for changelog ordering.
	time.Sleep(100 * time.Millisecond)

	resp, err = doWithAuth(t, http.MethodPost, srv.URL+ingestPath(t, pool, memberID), secondSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)

	var ingest2 map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingest2))
	resp.Body.Close()
	sbomID2 := ingest2["id"].(string)

	// --- Verify two SBOMs under same artifact ---
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/artifacts/%s/sboms", srv.URL, artifactID))
	is.NoErr(err)
	var sboms2 map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&sboms2))
	resp.Body.Close()
	is.Equal(len(sboms2["data"].([]any)), 2)

	// --- Test changelog ---
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/artifacts/%s/changelog", srv.URL, artifactID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)

	var changelog map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&changelog))
	resp.Body.Close()

	entries := changelog["entries"].([]any)
	is.Equal(len(entries), 1) // one diff between two SBOMs
	entry := entries[0].(map[string]any)
	summary := entry["summary"].(map[string]any)
	// adduser 3.118ubuntu2 → 3.118ubuntu5 = upgraded (direction-aware classification
	// per ADR-0021 §B1), apt was removed, curl was added.
	is.Equal(summary["added"], float64(1))    // curl
	is.Equal(summary["removed"], float64(1))  // apt
	is.Equal(summary["upgraded"], float64(1)) // adduser
	is.Equal(summary["modified"], float64(0))

	// --- Delete first SBOM ---
	resp, err = doWithAuth(t, http.MethodDelete, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomID1), "", memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusNoContent)
	resp.Body.Close()

	// --- Verify only one SBOM remains ---
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/artifacts/%s/sboms", srv.URL, artifactID))
	is.NoErr(err)
	var sboms3 map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&sboms3))
	resp.Body.Close()
	remaining := sboms3["data"].([]any)
	is.Equal(len(remaining), 1)
	is.Equal(remaining[0].(map[string]any)["id"], sbomID2)

	// --- Delete artifact (cascades to remaining SBOM) ---
	resp, err = doWithAuth(t, http.MethodDelete, fmt.Sprintf("%s/api/v1/artifacts/%s", srv.URL, artifactID), "", memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusNoContent)
	resp.Body.Close()

	// --- Verify artifact is gone ---
	resp, err = doGet(t, srv.URL+"/api/v1/artifacts?sufficient=false")
	is.NoErr(err)
	var empty map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&empty))
	resp.Body.Close()
	is.Equal(len(empty["data"].([]any)), 0)
}

func TestDigestNormalization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	memberID := seedUser(t, pool, 7002, "digest-norm-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "digest-test", "read-write")
	is.NoErr(err)

	// Syft-style: name without digest, version is digest
	syftSBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"component": {
				"type": "container",
				"name": "docker.io/ubuntu",
				"version": "sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214",
				"properties": [
					{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
					{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-01-01T00:00:00Z"}
				]
			},
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.version", "value": "20.04"}
			]
		},
		"components": [
			{"type": "library", "name": "bash", "version": "5.0"}
		]
	}`

	// Trivy-style: name includes digest, no version field (different digest than syftSBOM)
	trivySBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"component": {
				"type": "container",
				"name": "docker.io/ubuntu@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				"properties": [
					{"name": "aquasecurity:trivy:Labels:org.opencontainers.image.version", "value": "20.04"},
					{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
					{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-01-01T00:00:00Z"}
				]
			}
		},
		"components": [
			{"type": "library", "name": "bash", "version": "5.1"}
		]
	}`

	// Ingest both
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+ingestPath(t, pool, memberID), syftSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	resp.Body.Close()

	resp, err = doWithAuth(t, http.MethodPost, srv.URL+ingestPath(t, pool, memberID), trivySBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	resp.Body.Close()

	// Should be ONE artifact
	resp, err = doGet(t, srv.URL+"/api/v1/artifacts?sufficient=false")
	is.NoErr(err)
	var result map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&result))
	resp.Body.Close()

	artifacts := result["data"].([]any)
	is.Equal(len(artifacts), 1)
	art := artifacts[0].(map[string]any)
	is.Equal(art["name"], "docker.io/ubuntu")
	is.Equal(art["sbomCount"], float64(2))

	// Both SBOMs should have subject_version "20.04"
	artifactID := art["id"].(string)
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/artifacts/%s/sboms", srv.URL, artifactID))
	is.NoErr(err)
	var sbomsResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&sbomsResp))
	resp.Body.Close()

	sboms := sbomsResp["data"].([]any)
	is.Equal(len(sboms), 2)
	for _, s := range sboms {
		is.Equal(s.(map[string]any)["subjectVersion"], "20.04")
	}
}

// doGet performs an HTTP GET with the test context.
func doGet(t *testing.T, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

// TestArtifactDetailSigningStatusParity verifies the artifact detail endpoint
// (GET /api/v1/artifacts/{id}) reports the same aggregated signingStatus as the
// list endpoint (GET /api/v1/artifacts). Regression for ocidex-vbe: the detail
// query omitted signing_status entirely and always returned "".
func TestArtifactDetailSigningStatusParity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	memberID := seedUser(t, pool, 8100, "signing-parity-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "signing-parity-test", "read-write")
	is.NoErr(err)

	// Ingest an SBOM.
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+ingestPath(t, pool, memberID), minimalSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingestResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingestResp))
	resp.Body.Close()
	sbomID := ingestResp["id"].(string)

	// Resolve the artifact ID via the list endpoint; before enrichment both
	// surfaces should agree on "unsigned".
	listArtifact := firstArtifact(t, srv.URL, memberKey)
	artifactID := listArtifact["id"].(string)
	is.Equal(listArtifact["signingStatus"], "unsigned")

	// Seed a verified provenance enrichment for the ingested SBOM.
	_, err = pool.Exec(t.Context(),
		`INSERT INTO enrichment (sbom_id, enricher_name, status, data)
		 VALUES ($1::uuid, 'provenance', 'success', $2::jsonb)`,
		sbomID, `{"verified": true, "signaturePresent": true}`)
	is.NoErr(err)

	// List endpoint must now report "verified".
	listArtifact = firstArtifact(t, srv.URL, memberKey)
	is.Equal(listArtifact["signingStatus"], "verified")

	// Detail endpoint must report the SAME value (regression: was "").
	resp, err = doWithAuth(t, http.MethodGet, fmt.Sprintf("%s/api/v1/artifacts/%s", srv.URL, artifactID), "", memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var detailResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&detailResp))
	resp.Body.Close()
	is.Equal(detailResp["signingStatus"], "verified")
	is.Equal(detailResp["signingStatus"], listArtifact["signingStatus"])
}

// firstArtifact fetches the artifact list (all visibility) and returns the sole
// artifact map, failing if there is not exactly one.
func firstArtifact(t *testing.T, baseURL, apiKey string) map[string]any {
	t.Helper()
	is := is.New(t)
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/artifacts?sufficient=false", "", apiKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var listResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&listResp))
	resp.Body.Close()
	data := listResp["data"].([]any)
	is.Equal(len(data), 1)
	return data[0].(map[string]any)
}

// signingStatusFixtures covers all 5 terminal signing statuses, exercising
// the Go classifier (provenance.SigningStatus), the SBOM detail endpoint
// (Go-computed), and the artifact detail endpoint (SQL-computed) in one pass.
var signingStatusFixtures = []struct {
	name string
	data string // provenance enrichment JSON
	want string
}{
	{"unsigned", `{}`, "unsigned"},
	{"signed", `{"signaturePresent": true}`, "signed"},
	{"verified", `{"verified": true, "signaturePresent": true}`, "verified"},
	{"verification_failed", `{"verified": false, "signaturePresent": true}`, "verification_failed"},
	{"artifact_missing", `{"artifactMissing": true}`, "artifact_missing"},
}

// signingStatusSBOMTemplate is a minimal container SBOM parameterized by an
// index so each fixture resolves to a distinct artifact/digest.
//
// The index has to vary the *repository* name, not just the digest: artifact
// identity is the repository, so a shared one would put all five SBOMs under a
// single artifact and the artifact endpoint would return the rollup across
// them rather than this fixture's own status. That rollup is deliberate — see
// TestArtifactRollupSigningStatus_ArtifactMissingDominates — which is exactly
// why a parity test must not straddle it.
const signingStatusSBOMTemplate = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:11111111-1111-1111-1111-11111111111%d",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/signing-status-fixture-%d@sha256:%064d",
			"version": "1.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-02-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "adduser",
			"version": "3.118ubuntu2",
			"purl": "pkg:deb/ubuntu/adduser@3.118ubuntu2?arch=all&distro=ubuntu-24.04"
		}
	]
}`

// TestSigningStatusParity_AllStatuses verifies that for every terminal
// signing status, the Go classifier (provenance.SigningStatus), the SBOM
// detail endpoint's Go-computed signingStatus, and the artifact detail
// endpoint's SQL-computed signingStatus all agree. Regression coverage for
// ocidex-82g.3 (single source of truth for signing-status derivation).
func TestSigningStatusParity_AllStatuses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	memberID := seedUser(t, pool, 8200, "signing-status-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "signing-status-test", "read-write")
	is.New(t).NoErr(err)

	for i, fx := range signingStatusFixtures {
		t.Run(fx.name, func(t *testing.T) {
			is := is.New(t)

			// Go side: the classifier used by the SBOM detail endpoint.
			var p provenance.Provenance
			is.NoErr(json.Unmarshal([]byte(fx.data), &p))
			is.Equal(provenance.SigningStatus(p), fx.want)

			// Ingest a fixture-specific SBOM (distinct digest per fixture).
			sbomJSON := fmt.Sprintf(signingStatusSBOMTemplate, i, i, i)
			sbomID := mustIngest(t, srv.URL, ingestPath(t, pool, memberID), sbomJSON, memberKey)

			// Seed the provenance enrichment.
			_, err := pool.Exec(t.Context(),
				`INSERT INTO enrichment (sbom_id, enricher_name, status, data)
				 VALUES ($1::uuid, 'provenance', 'success', $2::jsonb)`,
				sbomID, fx.data)
			is.NoErr(err)

			// SBOM detail endpoint: Go-computed signingStatus.
			resp, err := doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomID))
			is.NoErr(err)
			is.Equal(resp.StatusCode, http.StatusOK)
			var sbomDetail map[string]any
			is.NoErr(json.NewDecoder(resp.Body).Decode(&sbomDetail))
			resp.Body.Close()
			is.Equal(sbomDetail["signingStatus"], fx.want)

			artifactID, ok := sbomDetail["artifactId"].(string)
			is.True(ok)

			// Artifact detail endpoint: SQL-computed signingStatus.
			resp, err = doGet(t, fmt.Sprintf("%s/api/v1/artifacts/%s", srv.URL, artifactID))
			is.NoErr(err)
			is.Equal(resp.StatusCode, http.StatusOK)
			var artifactDetail map[string]any
			is.NoErr(json.NewDecoder(resp.Body).Decode(&artifactDetail))
			resp.Body.Close()
			is.Equal(artifactDetail["signingStatus"], fx.want)
		})
	}
}

// TestArtifactRollupSigningStatus_ArtifactMissingDominates verifies the
// deliberate precedence inversion documented on GetArtifact/ListArtifacts in
// db/queries/artifact.sql (ocidex-goh.16): when an artifact has multiple
// SBOMs with different signing statuses, a single artifact_missing SBOM
// dominates the rollup even though a sibling SBOM under the same artifact
// still verifies. This is the one scenario where the rollup ladder's order
// is actually load-bearing — signing_status()'s single-row ladder never sees
// more than one status at a time, so its ordering has no such effect.
func TestArtifactRollupSigningStatus_ArtifactMissingDominates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	memberID := seedUser(t, pool, 8300, "signing-rollup-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "signing-rollup-test", "read-write")
	is.NoErr(err)

	// First SBOM: verified.
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+ingestPath(t, pool, memberID), minimalSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingest1 map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingest1))
	resp.Body.Close()
	sbomID1 := ingest1["id"].(string)

	_, err = pool.Exec(t.Context(),
		`INSERT INTO enrichment (sbom_id, enricher_name, status, data)
		 VALUES ($1::uuid, 'provenance', 'success', $2::jsonb)`,
		sbomID1, `{"verified": true, "signaturePresent": true}`)
	is.NoErr(err)

	// Second SBOM under the SAME artifact: artifact_missing.
	resp, err = doWithAuth(t, http.MethodPost, srv.URL+ingestPath(t, pool, memberID), secondSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingest2 map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingest2))
	resp.Body.Close()
	sbomID2 := ingest2["id"].(string)

	_, err = pool.Exec(t.Context(),
		`INSERT INTO enrichment (sbom_id, enricher_name, status, data)
		 VALUES ($1::uuid, 'provenance', 'success', $2::jsonb)`,
		sbomID2, `{"artifactMissing": true}`)
	is.NoErr(err)

	// Both SBOMs must belong to the one artifact, or this test proves nothing.
	artifact := firstArtifact(t, srv.URL, memberKey)
	artifactID := artifact["id"].(string)

	// Rollup must report artifact_missing, not verified — worst case wins.
	is.Equal(artifact["signingStatus"], "artifact_missing")

	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/artifacts/%s", srv.URL, artifactID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var detail map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&detail))
	resp.Body.Close()
	is.Equal(detail["signingStatus"], "artifact_missing")
}

// TestProvenanceRecheckErrorPreservesData covers ocidex-goh.2: a transient
// registry error during provenance reverification must not clobber a prior
// verified result. Exercises the exact sequence the reverifier hits UpsertEnrichment
// with (success, then a later error with no data), and asserts the SBOM keeps
// reporting "verified" and remains eligible for the next recheck sweep.
func TestProvenanceRecheckErrorPreservesData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	ctx := t.Context()

	memberID := seedUser(t, pool, 3001, "test-provenance-recheck", "member")
	memberKey, err := authSvc.CreateAPIKey(ctx, memberID, "test", "read-write")
	is.NoErr(err)

	sbomJSON := fmt.Sprintf(signingStatusSBOMTemplate, 99, 99, 99)
	sbomIDStr := mustIngest(t, srv.URL, ingestPath(t, pool, memberID), sbomJSON, memberKey)

	var sbomID pgtype.UUID
	is.NoErr(sbomID.Scan(sbomIDStr))

	queries := repository.New(pool)
	verifiedData := []byte(`{"verified": true, "signaturePresent": true}`)

	// The reverifier's first (successful) pass.
	is.NoErr(queries.UpsertEnrichment(ctx, repository.UpsertEnrichmentParams{
		SbomID:       sbomID,
		EnricherName: "provenance",
		Status:       "success",
		Data:         verifiedData,
	}))

	// A later recheck hits a transient registry error: no data, just an error.
	is.NoErr(queries.UpsertEnrichment(ctx, repository.UpsertEnrichmentParams{
		SbomID:       sbomID,
		EnricherName: "provenance",
		Status:       "error",
		ErrorMessage: pgtype.Text{String: "transient registry error", Valid: true},
	}))

	// The prior successful data and status must survive the error.
	stored, err := queries.GetEnrichment(ctx, repository.GetEnrichmentParams{
		SbomID:       sbomID,
		EnricherName: "provenance",
	})
	is.NoErr(err)
	is.Equal(stored.Status, "success")
	is.Equal(string(stored.Data), string(verifiedData))
	is.Equal(stored.ErrorMessage.String, "transient registry error")

	// The user-visible signing status must still read "verified", not fall back
	// to "unsigned" because the enrichment status flipped away from 'success'.
	resp, err := doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomIDStr))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var sbomDetail map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&sbomDetail))
	resp.Body.Close()
	is.Equal(sbomDetail["signingStatus"], "verified")

	// The SBOM must remain eligible for the next recheck sweep.
	due, err := queries.ListSBOMsDueForProvenanceRecheck(ctx, repository.ListSBOMsDueForProvenanceRecheckParams{
		Cutoff:   pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		RowLimit: 10,
	})
	is.NoErr(err)
	found := false
	for _, id := range due {
		if id.Bytes == sbomID.Bytes {
			found = true
			break
		}
	}
	is.True(found)
}

// fakeProvenanceEnricher returns fixed provenance JSON for every subject,
// standing in for the real provenance enricher so tests can drive
// Dispatcher.ProcessOne directly against a real Postgres-backed Store.
type fakeProvenanceEnricher struct {
	data []byte
}

func (f *fakeProvenanceEnricher) Name() string                           { return "provenance" }
func (f *fakeProvenanceEnricher) CanEnrich(_ enrichment.SubjectRef) bool { return true }
func (f *fakeProvenanceEnricher) Enrich(_ context.Context, _ enrichment.SubjectRef) ([]byte, error) {
	return f.data, nil
}

// TestProvenanceDriftFullCycle drives the real Dispatcher/Store against
// Postgres for a verified -> regressed transition, then confirms the
// resulting provenance_drift_events row is visible via the SBOM
// drift-history API. Regression coverage for ocidex-goh.10.
func TestProvenanceDriftFullCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	ctx := t.Context()

	memberID := seedUser(t, pool, 3100, "test-drift-cycle", "member")
	memberKey, err := authSvc.CreateAPIKey(ctx, memberID, "test", "read-write")
	is.NoErr(err)

	sbomJSON := fmt.Sprintf(signingStatusSBOMTemplate, 98, 98, 98)
	sbomIDStr := mustIngest(t, srv.URL, ingestPath(t, pool, memberID), sbomJSON, memberKey)

	var sbomID pgtype.UUID
	is.NoErr(sbomID.Scan(sbomIDStr))

	queries := repository.New(pool)

	// Seed the initial verified provenance enrichment, as if the real
	// provenance enricher already ran once successfully.
	verifiedData := []byte(`{"verified": true, "signaturePresent": true, "signerFingerprint": "abc123"}`)
	is.NoErr(queries.UpsertEnrichment(ctx, repository.UpsertEnrichmentParams{
		SbomID:       sbomID,
		EnricherName: "provenance",
		Status:       "success",
		Data:         verifiedData,
	}))

	resp, err := doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomIDStr))
	is.NoErr(err)
	var before map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&before))
	resp.Body.Close()
	is.Equal(before["signingStatus"], "verified")

	// Drive a real reverification pass through the actual Dispatcher/Store:
	// same signer, but the trust config now rejects it.
	regressedData := []byte(`{"verified": false, "signaturePresent": true, "signerFingerprint": "abc123"}`)
	catalog := enrichment.NewCatalog()
	catalog.Register(&fakeProvenanceEnricher{data: regressedData})
	dispatcher := enrichment.NewDispatcher(queries, catalog)
	is.NoErr(dispatcher.ProcessOne(ctx, enrichment.SubjectRef{
		SBOMId:       sbomID,
		ArtifactType: "container",
		ArtifactName: "docker.io/signing-status-fixture",
	}))

	// The regression must be visible in the SBOM's signing status...
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomIDStr))
	is.NoErr(err)
	var after map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&after))
	resp.Body.Close()
	is.Equal(after["signingStatus"], "verification_failed")

	// ...and as a recorded drift event, visible via the drift-history API.
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s/drift", srv.URL, sbomIDStr))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var driftResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&driftResp))
	resp.Body.Close()

	data, ok := driftResp["data"].([]any)
	is.True(ok)
	is.Equal(len(data), 1)
	event := data[0].(map[string]any)
	is.Equal(event["previousStatus"], "verified")
	is.Equal(event["newStatus"], "verification_failed")
	is.Equal(event["reason"], "trust_config_changed")
}
