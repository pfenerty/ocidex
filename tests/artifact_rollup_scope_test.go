package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
)

// Scope of the artifact list's rollup columns (ocidex-7gf7.2, ocidex-7gf7.3).
//
// Both columns on an /artifacts row summarise many SBOMs into one value, and
// each got its precedence wrong in a way no existing test could see: the
// vulnerability counts picked the most recently *ingested* SBOM rather than the
// latest version, and the signing ladder let a passing sibling mask one whose
// signature had actually failed.

// scopeSBOMTemplate is a container SBOM parameterised by serial suffix, digest,
// subject version, and its single package. Every fixture below shares one
// repository name on purpose — the artifact is the repository, so sharing it is
// what puts these SBOMs under one rollup.
const scopeSBOMTemplate = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:22222222-2222-2222-2222-22222222222%d",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/rollup-scope-fixture@sha256:%064d",
			"version": "%s",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-03-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "%s",
			"version": "1.0.0",
			"purl": "pkg:generic/%s@1.0.0"
		}
	]
}`

func scopeSBOM(serial, digest int, version, pkg string) string {
	return fmt.Sprintf(scopeSBOMTemplate, serial, digest, version, pkg, pkg)
}

// seedFinding records one advisory against one package purl.
func seedFinding(t *testing.T, pool *pgxpool.Pool, cve, severity, pkg string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO vulnerability (id, severity, summary) VALUES ($1, $2, $3)
		 ON CONFLICT (id) DO NOTHING`, cve, severity, "seeded "+cve); err != nil {
		t.Fatalf("seeding vulnerability: %v", err)
	}
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO package_vulnerability (purl, vulnerability_id)
		 VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		"pkg:generic/"+pkg+"@1.0.0", cve); err != nil {
		t.Fatalf("seeding package_vulnerability: %v", err)
	}
}

// artifactListEntry reads the single artifact off the list endpoint. The list,
// not the detail endpoint: the scope under test is ListArtifacts' lateral, and
// the detail endpoint does not carry these counts.
func artifactListEntry(t *testing.T, baseURL, apiKey string) map[string]any {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet,
		baseURL+"/api/v1/artifacts?limit=50&sufficient=false", "", apiKey)
	if err != nil {
		t.Fatalf("listing artifacts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing artifacts: status %d", resp.StatusCode)
	}
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding artifact list: %v", err)
	}
	for _, a := range body.Data {
		if a["name"] == "docker.io/rollup-scope-fixture" {
			return a
		}
	}
	t.Fatalf("fixture artifact not in list of %d", len(body.Data))
	return nil
}

// TestArtifactRollupVulns_LatestVersionNotLatestIngest pins the fix for the bug
// that made the /artifacts vulnerability column untrustworthy: it ordered by
// created_at, so re-scanning or backfilling an old tag rewrote the row's counts
// to that old tag's findings.
//
// The fixture is that scenario exactly — the older version is ingested second,
// so "newest row" and "latest version" point at different SBOMs and disagree
// about severity.
func TestArtifactRollupVulns_LatestVersionNotLatestIngest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	memberID := seedUser(t, pool, 8401, "rollup-scope-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "rollup-scope", nil)
	is.NoErr(err)
	path := ingestPath(t, pool, memberID)

	// v2.0.0 first: the latest version, and the older row.
	mustIngest(t, srv.URL, path, scopeSBOM(1, 1, "v2.0.0", "calm-lib"), memberKey)
	// v1.0.0 second: the superseded version, and the newest row — a backfill.
	mustIngest(t, srv.URL, path, scopeSBOM(2, 2, "v1.0.0", "scary-lib"), memberKey)

	seedFinding(t, pool, "CVE-2026-10001", "LOW", "calm-lib")
	seedFinding(t, pool, "CVE-2026-10002", "CRITICAL", "scary-lib")

	refreshRollups(t, pool)

	entry := artifactListEntry(t, srv.URL, memberKey)
	vulns, ok := entry["vulns"].(map[string]any)
	if !ok {
		t.Fatalf("artifact has no vulns summary: %v", entry)
	}

	// The whole point: the CRITICAL belongs to the superseded version, which
	// happens to be the newest row. Reporting it here is what the old ordering
	// did, and it is what made the column change under a backfill.
	is.Equal(vulns["critical"], float64(0))
	is.Equal(vulns["low"], float64(1))
}

// TestArtifactRollupSigningStatus_FailureBeatsVerified pins the other half of
// the ladder. artifact_missing was already hoisted (see
// TestArtifactRollupSigningStatus_ArtifactMissingDominates), but everything
// below it was best-first, so verified was tested before verification_failed
// and one passing sibling hid a signature that had genuinely failed to verify —
// the stronger signal masked by the weaker one.
func TestArtifactRollupSigningStatus_FailureBeatsVerified(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	memberID := seedUser(t, pool, 8402, "signing-ladder-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "signing-ladder", nil)
	is.NoErr(err)
	path := ingestPath(t, pool, memberID)

	verifiedID := mustIngest(t, srv.URL, path, scopeSBOM(3, 3, "v1.0.0", "calm-lib"), memberKey)
	failedID := mustIngest(t, srv.URL, path, scopeSBOM(4, 4, "v1.1.0", "calm-lib"), memberKey)

	for _, s := range []struct{ id, data string }{
		{verifiedID, `{"verified": true, "signaturePresent": true}`},
		{failedID, `{"verified": false, "signaturePresent": true}`},
	} {
		_, err := pool.Exec(t.Context(),
			`INSERT INTO enrichment (sbom_id, enricher_name, status, data)
			 VALUES ($1::uuid, 'provenance', 'success', $2::jsonb)`, s.id, s.data)
		is.NoErr(err)
	}

	refreshRollups(t, pool)

	// Both the list and the detail endpoint carry their own copy of the ladder,
	// so both are asserted — a fix applied to one and not the other is exactly
	// how they would drift.
	is.Equal(artifactListEntry(t, srv.URL, memberKey)["signingStatus"], "verification_failed")

	artifactID, ok := artifactListEntry(t, srv.URL, memberKey)["id"].(string)
	is.True(ok)
	resp, err := doWithAuth(t, http.MethodGet,
		srv.URL+"/api/v1/artifacts/"+artifactID, "", memberKey)
	is.NoErr(err)
	defer resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusOK)
	var detail map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&detail))
	is.Equal(detail["signingStatus"], "verification_failed")
}
