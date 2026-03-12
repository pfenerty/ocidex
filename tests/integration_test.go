package tests

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/matryer/is"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/pfenerty/ocidex/db"
	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/service"
)

// requireDocker skips the test if Docker is not available.
func requireDocker(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker not available, skipping integration test")
	}
}

// setupTestDB starts a Postgres container, runs migrations, and returns a pool + cleanup func.
func setupTestDB(t *testing.T) (*pgxpool.Pool, func()) {
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

	// Run migrations.
	sqlDB, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("opening migration connection: %v", err)
	}
	goose.SetBaseFS(db.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("setting dialect: %v", err)
	}
	if err := goose.Up(sqlDB, "migrations"); err != nil {
		t.Fatalf("running migrations: %v", err)
	}
	sqlDB.Close()

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("creating pool: %v", err)
	}

	cleanup := func() {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
	}

	return pool, cleanup
}

// setupServer creates a fully-wired test HTTP server.
func setupServer(t *testing.T, pool *pgxpool.Pool) *httptest.Server {
	t.Helper()
	sbomSvc := service.NewSBOMService(pool, nil, nil)
	searchSvc := service.NewSearchService(pool)
	handler := api.NewHandler(sbomSvc, searchSvc, nil, nil, pool, nil, nil)
	router := api.NewRouter(handler, "*", "")
	return httptest.NewServer(router)
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

func TestFullLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv := setupServer(t, pool)
	defer srv.Close()

	is := is.New(t)

	// --- Ingest first SBOM ---
	resp, err := doPost(t, srv.URL+"/api/v1/sboms", strings.NewReader(minimalSBOM))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)

	var ingestResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingestResp))
	resp.Body.Close()
	sbomID1 := ingestResp["id"].(string)
	is.True(sbomID1 != "")
	is.Equal(ingestResp["componentCount"], float64(2))

	// --- Verify artifact was created ---
	resp, err = doGet(t, srv.URL+"/api/v1/artifacts")
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

	resp, err = doPost(t, srv.URL+"/api/v1/sboms", strings.NewReader(secondSBOM))
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
	// adduser was modified (version changed), apt was removed, curl was added
	is.Equal(summary["added"], float64(1))    // curl
	is.Equal(summary["removed"], float64(1))  // apt
	is.Equal(summary["modified"], float64(1)) // adduser

	// --- Delete first SBOM ---
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodDelete, fmt.Sprintf("%s/api/v1/sboms/%s", srv.URL, sbomID1), nil)
	resp, err = http.DefaultClient.Do(req)
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
	req, _ = http.NewRequestWithContext(t.Context(), http.MethodDelete, fmt.Sprintf("%s/api/v1/artifacts/%s", srv.URL, artifactID), nil)
	resp, err = http.DefaultClient.Do(req)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusNoContent)
	resp.Body.Close()

	// --- Verify artifact is gone ---
	resp, err = doGet(t, srv.URL+"/api/v1/artifacts")
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
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv := setupServer(t, pool)
	defer srv.Close()

	is := is.New(t)

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
	resp, err := doPost(t, srv.URL+"/api/v1/sboms", strings.NewReader(syftSBOM))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	resp.Body.Close()

	resp, err = doPost(t, srv.URL+"/api/v1/sboms", strings.NewReader(trivySBOM))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	resp.Body.Close()

	// Should be ONE artifact
	resp, err = doGet(t, srv.URL+"/api/v1/artifacts")
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

// doPost performs an HTTP POST with the test context (always application/json).
func doPost(t *testing.T, url string, body *strings.Reader) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req)
}
