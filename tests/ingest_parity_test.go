package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
)

// richSBOM exercises every batched-CopyFrom write path: a nested component tree
// (parent → child), multiple hashes, SPDX + non-SPDX licenses, external
// references, and a license (MIT) shared across two components so dedup is
// covered. The `secret` component is added as a NULL-parent sibling.
const richSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/rich@sha256:ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"version": "1.0.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-03-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "parent-lib",
			"version": "1.2.3",
			"purl": "pkg:generic/parent-lib@1.2.3",
			"hashes": [
				{"alg": "SHA-256", "content": "aaaa1111"},
				{"alg": "SHA-1", "content": "bbbb2222"}
			],
			"licenses": [
				{"license": {"id": "MIT"}},
				{"license": {"name": "Proprietary EULA"}}
			],
			"externalReferences": [
				{"type": "website", "url": "https://parent.example.com"},
				{"type": "vcs", "url": "https://github.com/example/parent"}
			],
			"components": [
				{
					"type": "library",
					"name": "child-lib",
					"version": "0.1.0",
					"purl": "pkg:generic/child-lib@0.1.0",
					"licenses": [
						{"license": {"id": "MIT"}}
					]
				}
			]
		},
		{
			"type": "library",
			"name": "sibling-lib",
			"version": "2.0.0",
			"purl": "pkg:generic/sibling-lib@2.0.0"
		}
	]
}`

// TestIngestParity_CopyFromRoundTrip ingests a structurally rich SBOM and reads
// the persisted rows back directly from the database, asserting the batched
// CopyFrom pipeline reproduces the component tree (incl. parent_id wiring),
// hashes, external references, and deduplicated licenses.
func TestIngestParity_CopyFromRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	ctx := t.Context()

	memberID := seedUser(t, pool, 7301, "parity-member", "member")
	memberKey, err := authSvc.CreateAPIKey(ctx, memberID, "parity-test", "read-write")
	is.NoErr(err)

	// --- Ingest ---
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", richSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingest map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingest))
	resp.Body.Close()
	sbomID := ingest["id"].(string)
	is.True(sbomID != "")
	is.Equal(ingest["componentCount"], float64(2)) // top-level: parent, sibling

	// --- Component tree + parent_id wiring (full tree, incl. nested child) ---
	ids := componentIDsByName(ctx, t, pool, sbomID)
	is.Equal(len(ids), 3) // parent, child, sibling

	parentParent := parentIDOf(ctx, t, pool, ids["parent-lib"])
	siblingParent := parentIDOf(ctx, t, pool, ids["sibling-lib"])
	childParent := parentIDOf(ctx, t, pool, ids["child-lib"])
	is.True(!parentParent.Valid)             // top-level → NULL parent
	is.True(!siblingParent.Valid)            // top-level → NULL parent
	is.True(childParent.Valid)               // nested → has parent
	is.Equal(childParent, ids["parent-lib"]) // child wired to parent's generated id

	// --- Hashes (parent only) ---
	is.Equal(countRows(ctx, t, pool,
		"SELECT count(*) FROM component_hash WHERE component_id = $1", ids["parent-lib"]), 2)
	is.Equal(countRows(ctx, t, pool,
		"SELECT count(*) FROM component_hash WHERE component_id = $1", ids["sibling-lib"]), 0)

	// --- External references (parent only) ---
	is.Equal(countRows(ctx, t, pool,
		"SELECT count(*) FROM external_reference WHERE component_id = $1", ids["parent-lib"]), 2)

	// --- Licenses: MIT (SPDX) reused across parent+child, Proprietary (non-SPDX) ---
	is.Equal(countRows(ctx, t, pool,
		"SELECT count(*) FROM license WHERE spdx_id = 'MIT'"), 1) // single shared row
	is.Equal(countRows(ctx, t, pool,
		"SELECT count(*) FROM component_license WHERE component_id = $1", ids["parent-lib"]), 2) // MIT + Proprietary
	is.Equal(countRows(ctx, t, pool,
		"SELECT count(*) FROM component_license WHERE component_id = $1", ids["child-lib"]), 1) // MIT
	is.Equal(countRows(ctx, t, pool,
		"SELECT count(*) FROM component_license WHERE component_id = $1", ids["sibling-lib"]), 0)

	// MIT license id is identical for parent and child (true dedup, not two rows).
	is.Equal(licenseIDForComponent(ctx, t, pool, ids["parent-lib"], "MIT"),
		licenseIDForComponent(ctx, t, pool, ids["child-lib"], "MIT"))
}

func componentIDsByName(ctx context.Context, t *testing.T, pool *pgxpool.Pool, sbomID string) map[string]pgtype.UUID {
	t.Helper()
	rows, err := pool.Query(ctx,
		"SELECT name, id FROM component WHERE sbom_id = $1", sbomID)
	if err != nil {
		t.Fatalf("querying components: %v", err)
	}
	defer rows.Close()
	out := map[string]pgtype.UUID{}
	for rows.Next() {
		var name string
		var id pgtype.UUID
		if err := rows.Scan(&name, &id); err != nil {
			t.Fatalf("scanning component: %v", err)
		}
		out[name] = id
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating components: %v", err)
	}
	return out
}

func parentIDOf(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id pgtype.UUID) pgtype.UUID {
	t.Helper()
	var parent pgtype.UUID
	if err := pool.QueryRow(ctx,
		"SELECT parent_id FROM component WHERE id = $1", id).Scan(&parent); err != nil {
		t.Fatalf("querying parent_id: %v", err)
	}
	return parent
}

func licenseIDForComponent(ctx context.Context, t *testing.T, pool *pgxpool.Pool, compID pgtype.UUID, spdxID string) pgtype.UUID {
	t.Helper()
	var id pgtype.UUID
	if err := pool.QueryRow(ctx, `
		SELECT l.id FROM license l
		JOIN component_license cl ON cl.license_id = l.id
		WHERE cl.component_id = $1 AND l.spdx_id = $2`, compID, spdxID).Scan(&id); err != nil {
		t.Fatalf("querying license id: %v", err)
	}
	return id
}

func countRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}
