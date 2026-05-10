package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/matryer/is"
)

// mainModuleBackfillSBOM has:
//   - metadata.properties.image.source = github.com/example/svc.git → main module is github.com/example/svc
//   - metadata.properties.image.version = v1.5.0 → subject version
//   - One component with name=github.com/example/svc, version="UNKNOWN" (the main module Syft couldn't pin)
//   - One component with name=github.com/example/svc/internal, version="UNKNOWN" (a submodule — must NOT be backfilled)
//   - One regular library at v1.0.0
const mainModuleBackfillSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:8a1d39e0-4711-4711-4711-471147114711",
	"metadata": {
		"component": {
			"type": "container",
			"name": "ghcr.io/example/svc@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			"version": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		},
		"properties": [
			{"name": "syft:image:labels:org.opencontainers.image.source", "value": "https://github.com/example/svc.git"},
			{"name": "syft:image:labels:org.opencontainers.image.version", "value": "v1.5.0"},
			{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
			{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-04-01T00:00:00Z"}
		]
	},
	"components": [
		{
			"type": "library",
			"name": "github.com/example/svc",
			"version": "UNKNOWN",
			"purl": "pkg:golang/github.com/example/svc"
		},
		{
			"type": "library",
			"name": "github.com/example/svc/internal",
			"version": "UNKNOWN",
			"purl": "pkg:golang/github.com/example/svc/internal"
		},
		{
			"type": "library",
			"name": "github.com/spf13/cobra",
			"version": "v1.0.0",
			"purl": "pkg:golang/github.com/spf13/cobra@v1.0.0"
		}
	]
}`

// TestMainModuleVersionBackfill verifies that ingest backfills the version of
// the SBOM's main module (Go package whose source repo matches the image
// source label) when Syft emitted "UNKNOWN". Submodules and unrelated
// components keep their original version.
func TestMainModuleVersionBackfill(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	memberID := seedUser(t, pool, 9101, "main-mod-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "main-mod-test", "read-write")
	is.NoErr(err)

	// Ingest the SBOM.
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", mainModuleBackfillSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingest map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingest))
	resp.Body.Close()
	sbomID := ingest["id"].(string)

	// Fetch the SBOM's components.
	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s/components", srv.URL, sbomID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var compsResp map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&compsResp))
	resp.Body.Close()

	byName := map[string]map[string]any{}
	for _, c := range compsResp["components"].([]any) {
		cm := c.(map[string]any)
		byName[cm["name"].(string)] = cm
	}

	// Main module: backfilled to v1.5.0 (subject version from image.version property).
	main := byName["github.com/example/svc"]
	is.True(main != nil)
	is.Equal(main["version"], "v1.5.0")

	// Submodule: NOT backfilled. The version stays UNKNOWN — this is intentional
	// per ADR-0019 / main_module.go: only the exact path match is backfilled.
	sub := byName["github.com/example/svc/internal"]
	is.True(sub != nil)
	is.Equal(sub["version"], "UNKNOWN")

	// Unrelated dependency: untouched.
	cobra := byName["github.com/spf13/cobra"]
	is.True(cobra != nil)
	is.Equal(cobra["version"], "v1.0.0")
}

// TestMainModuleVersionBackfillMigration exercises the SQL migration directly
// against rows that were inserted before the backfill rule existed in the
// ingest path. Simulates a real upgrade: write rows with version='UNKNOWN'
// straight into the DB, then run the migration's UPDATE statements (re-run
// migration 26 by replaying its body) and assert the rows were backfilled.
func TestMainModuleVersionBackfillMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	is := is.New(t)
	ctx := context.Background()

	// Reset the rows we touch to a pre-migration shape: insert a synthetic SBOM
	// whose raw_bom carries the syft image.source label, plus a Go main-module
	// component with version=UNKNOWN.
	const rawBom = `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.source", "value": "https://github.com/legacy/svc.git"}
			]
		}
	}`

	// Seed an artifact + sbom + components by hand.
	var artifactID, sbomID string
	err := pool.QueryRow(ctx,
		`INSERT INTO artifact (type, name) VALUES ('container', 'legacy/svc') RETURNING id`,
	).Scan(&artifactID)
	is.NoErr(err)

	err = pool.QueryRow(ctx,
		`INSERT INTO sbom (artifact_id, spec_version, version, raw_bom, subject_version)
		 VALUES ($1, '1.6', 1, $2::jsonb, $3) RETURNING id`,
		artifactID, rawBom, "v0.9.0",
	).Scan(&sbomID)
	is.NoErr(err)

	// Main module — UNKNOWN version, must be backfilled.
	_, err = pool.Exec(ctx,
		`INSERT INTO component (sbom_id, type, name, version, purl)
		 VALUES ($1, 'library', 'github.com/legacy/svc', 'UNKNOWN', 'pkg:golang/github.com/legacy/svc')`,
		sbomID,
	)
	is.NoErr(err)

	// Submodule — UNKNOWN version, must NOT be backfilled.
	_, err = pool.Exec(ctx,
		`INSERT INTO component (sbom_id, type, name, version, purl)
		 VALUES ($1, 'library', 'github.com/legacy/svc/internal', 'UNKNOWN', 'pkg:golang/github.com/legacy/svc/internal')`,
		sbomID,
	)
	is.NoErr(err)

	// Concrete-version dep — must stay v1.0.0.
	_, err = pool.Exec(ctx,
		`INSERT INTO component (sbom_id, type, name, version, purl)
		 VALUES ($1, 'library', 'github.com/spf13/cobra', 'v1.0.0', 'pkg:golang/github.com/spf13/cobra@v1.0.0')`,
		sbomID,
	)
	is.NoErr(err)

	// The setupTestDB helper already ran migration 00026; replay its UPDATE so
	// the test simulates "rows existed before the migration ran" semantics.
	// (Idempotent: running again is a no-op for already-correct rows.)
	const replayMigration = `
		WITH source_per_sbom AS (
		    SELECT s.id AS sbom_id, s.subject_version,
		      COALESCE(
		        (SELECT prop->>'value' FROM jsonb_array_elements(COALESCE(s.raw_bom #> '{metadata,component,properties}', '[]'::jsonb)) AS prop
		         WHERE prop->>'name' IN ('syft:image:labels:org.opencontainers.image.source','aquasecurity:trivy:Labels:org.opencontainers.image.source') AND prop->>'value' <> '' LIMIT 1),
		        (SELECT prop->>'value' FROM jsonb_array_elements(COALESCE(s.raw_bom #> '{metadata,properties}', '[]'::jsonb)) AS prop
		         WHERE prop->>'name' IN ('syft:image:labels:org.opencontainers.image.source','aquasecurity:trivy:Labels:org.opencontainers.image.source') AND prop->>'value' <> '' LIMIT 1)
		      ) AS raw_source
		    FROM sbom s WHERE s.subject_version IS NOT NULL AND s.subject_version <> ''
		),
		main_module AS (
		    SELECT sbom_id, subject_version,
		      regexp_replace(regexp_replace(regexp_replace(raw_source, '^[a-zA-Z+]+://', ''), '^[^/]*@', ''), '(\.git)?/?$', '') AS module_path
		    FROM source_per_sbom WHERE raw_source IS NOT NULL AND raw_source <> ''
		)
		UPDATE component c SET version = mm.subject_version
		FROM main_module mm
		WHERE c.sbom_id = mm.sbom_id
		  AND (c.version = 'UNKNOWN' OR c.version IS NULL OR c.version = '')
		  AND mm.module_path <> ''
		  AND (
		      regexp_replace(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '[@?].*$', '') = mm.module_path
		      OR (c.purl IS NULL AND c.name = mm.module_path)
		  );
	`
	_, err = pool.Exec(ctx, replayMigration)
	is.NoErr(err)

	// Verify outcomes.
	versions := map[string]string{}
	rows, err := pool.Query(ctx, "SELECT name, version FROM component WHERE sbom_id = $1", sbomID)
	is.NoErr(err)
	for rows.Next() {
		var name, ver string
		is.NoErr(rows.Scan(&name, &ver))
		versions[name] = ver
	}
	rows.Close()

	is.Equal(versions["github.com/legacy/svc"], "v0.9.0")           // backfilled
	is.Equal(versions["github.com/legacy/svc/internal"], "UNKNOWN") // submodule untouched
	is.Equal(versions["github.com/spf13/cobra"], "v1.0.0")          // concrete version preserved
}
