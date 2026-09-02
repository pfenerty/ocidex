package tests

import (
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
)

// Latency budget for the read path (ocidex-7gf7.1).
//
// Three endpoints reached production exceeding router.go's 30s
// middleware.Timeout, and none of them failed a test on the way there: every
// existing integration test seeds a handful of SBOMs, where an unbounded query
// and a bounded one are indistinguishable. This file is the fixture that tells
// them apart — one artifact wide enough that work proportional to its width
// costs real time — plus the assertion that no endpoint spends more than a
// fraction of the ceiling on it.
//
// The budget is deliberately the same constant the server warns at
// (api.slowRequestThreshold), so "CI failed" and "production logged a warning"
// mean the same thing rather than two thresholds drifting apart.

const (
	// latencyBudget is per request. Well under the 30s timeout: by the time a
	// request times out a user has already seen the failure, so the guard has
	// to fire while an endpoint is merely getting slow.
	latencyBudget = 5 * time.Second

	// widthVersions and widthComponents size the fixture, matching the shape of
	// production's worst artifact (4,074 SBOMs across 1,025 versions at ~1,093
	// components each) closely enough that work proportional to it costs real
	// time.
	//
	// These were calibrated, not guessed. At 600 x 300 with identical package
	// sets the unbounded changelog answered in 0.25s and the unbounded
	// /artifacts/{id}/vulns in under 0.01s — a guard that size would have
	// passed against the exact bugs it exists to catch. At 1000 x 900 with
	// drift and seeded findings, /vulns takes 24.8s and the changelog 4.2s,
	// which is the production failure reproduced. Seeding is a few
	// INSERT ... SELECTs rather than repeated ingest, which is what makes this
	// size affordable (~60s).
	//
	// The changelog's 4.2s clears the budget only narrowly, so time alone is a
	// weak guard for it; ocidex-7gf7.4 adds the deterministic assertion (the
	// response holds at most `limit` entries) that does not depend on machine
	// speed at all.
	widthVersions   = 1000
	widthComponents = 900

	// componentDrift is how far each version shifts its package names. Without
	// it every version holds an identical package set, every changelog diff is
	// empty, and the diff path costs nothing however many versions it walks —
	// which is the other half of why a naive fixture cannot reproduce this.
	componentDrift = 40
)

// wideArtifactSBOM is the seed the fixture is cloned from. It goes in through
// the real ingest path so artifact, artifact_namespace and source linkage are
// built the way production builds them; only the bulk copies are raw SQL.
const wideArtifactSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:7f000000-0000-0000-0000-000000000001",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "registry.test/wide@sha256:7f00000000000000000000000000000000000000000000000000000000000001",
			"version": "v1.0.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-01-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{"type": "library", "name": "pkg-1", "version": "1.0.1", "purl": "pkg:generic/pkg-1@1.0.1"}
	]
}`

// seedWideArtifact clones the ingested SBOM into widthVersions versions and
// gives each clone widthComponents packages, returning the artifact and the
// original SBOM's ids.
//
// The clone is raw SQL rather than repeated ingest because the cost being
// guarded against is on the read path: what matters is that the rows exist in
// the shape the reader will meet, not that each one went through the parser.
func seedWideArtifact(t *testing.T, pool *pgxpool.Pool, baseURL, apiKey, sourceID string) (artifactID, sbomID string) {
	t.Helper()

	ingestOK(t, baseURL, apiKey, "/api/v1/sboms?source="+sourceID, wideArtifactSBOM)

	var aID, sID pgtype.UUID
	err := pool.QueryRow(t.Context(),
		`SELECT s.artifact_id, s.id FROM sbom s
		 JOIN artifact a ON a.id = s.artifact_id
		 WHERE a.name = 'registry.test/wide'`).Scan(&aID, &sID)
	if err != nil {
		t.Fatalf("locating seed SBOM: %v", err)
	}

	// Each clone gets its own serial number and digest — both are meant to be
	// unique per SBOM, and a fixture that violates that would be testing a
	// shape the reader never sees.
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO sbom (serial_number, spec_version, version, raw_bom, created_at,
		                   artifact_id, subject_version, digest, enrichment_sufficient,
		                   namespace_id, flavor, source_id)
		 SELECT 'urn:uuid:' || gen_random_uuid(),
		        s.spec_version, 1, '{}'::jsonb,
		        s.created_at + (v.n || ' minutes')::interval,
		        s.artifact_id,
		        'v1.' || v.n || '.0',
		        'sha256:' || md5('wide-' || v.n::text),
		        true,
		        s.namespace_id, s.flavor, s.source_id
		 FROM sbom s CROSS JOIN generate_series(1, $2) AS v(n)
		 WHERE s.id = $1`, sID, widthVersions); err != nil {
		t.Fatalf("cloning SBOMs: %v", err)
	}

	// Package names shift with the version so consecutive versions genuinely
	// differ, which is what gives the changelog diffs something to compute.
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO component (sbom_id, type, name, version,
		                        version_major, version_minor, version_patch, purl)
		 SELECT s.id, 'library',
		        'pkg-' || (c.n + (COALESCE(s.version_minor, 0) % $4)),
		        '1.0.' || (c.n % 7),
		        1, 0, c.n % 7,
		        'pkg:generic/pkg-' || (c.n + (COALESCE(s.version_minor, 0) % $4)) || '@1.0.' || (c.n % 7)
		 FROM sbom s CROSS JOIN generate_series(1, $3) AS c(n)
		 WHERE s.artifact_id = $1 AND s.id <> $2`,
		aID, sID, widthComponents, componentDrift); err != nil {
		t.Fatalf("cloning components: %v", err)
	}

	// A vulnerability store with findings against a share of those packages.
	// With none, the vulnerability endpoints answer instantly whatever they
	// scan, and the budget says nothing about them.
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO vulnerability (id, severity, cvss_score, summary)
		 SELECT 'CVE-2026-' || lpad(n::text, 5, '0'),
		        (ARRAY['CRITICAL','HIGH','MEDIUM','LOW'])[1 + (n % 4)],
		        9.8 - (n % 4),
		        'seeded finding ' || n
		 FROM generate_series(1, $1) AS n`, widthComponents); err != nil {
		t.Fatalf("seeding vulnerabilities: %v", err)
	}
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO package_vulnerability (purl, vulnerability_id, fixed_version)
		 SELECT DISTINCT c.purl, 'CVE-2026-' || lpad(((c.version_patch * 7) + 1)::text, 5, '0'), '9.9.9'
		 FROM component c
		 JOIN sbom s ON s.id = c.sbom_id
		 WHERE s.artifact_id = $1 AND c.purl IS NOT NULL
		 ON CONFLICT DO NOTHING`, aID); err != nil {
		t.Fatalf("seeding package vulnerabilities: %v", err)
	}

	if _, err := pool.Exec(t.Context(), `ANALYZE sbom; ANALYZE component; ANALYZE package_vulnerability;`); err != nil {
		t.Fatalf("analyzing: %v", err)
	}

	return uuidString(t, aID), uuidString(t, sID)
}

// TestReadPathLatencyBudget walks every GET whose cost scales with the size of
// the data behind it and asserts each stays inside the budget.
func TestReadPathLatencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7701, "latency-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", nil)
	is.NoErr(err)

	nsID := seedNamespace(t, pool, "latency-ns", ownerID, "public")
	srcID := seedSource(t, pool, nsID, "oci_registry", "ghcr")

	artifactID, sbomID := seedWideArtifact(t, pool, srv.URL, ownerKey, srcID)
	refreshRollups(t, pool)

	cases := []struct {
		name string
		path string
		// skip names the issue that will make this endpoint bounded. An
		// endpoint listed here is known to scale with artifact width today;
		// the story that fixes it clears this field, which is what turns this
		// table into the epic's own checklist.
		skip string
	}{
		{name: "artifact list", path: "/api/v1/artifacts?limit=50"},
		{name: "artifact list by severity", path: "/api/v1/artifacts?limit=50&sort=severity&dir=desc"},
		{name: "artifact detail", path: "/api/v1/artifacts/" + artifactID},
		{name: "artifact vuln summary", path: "/api/v1/artifacts/" + artifactID + "/vuln-summary"},
		{name: "artifact license summary", path: "/api/v1/artifacts/" + artifactID + "/license-summary"},
		{name: "artifact contains", path: "/api/v1/artifacts/" + artifactID + "/contains"},
		{name: "artifact usages", path: "/api/v1/artifacts/" + artifactID + "/usages"},
		{name: "artifact versions", path: "/api/v1/artifacts/" + artifactID + "/versions?limit=50"},
		{name: "sbom components", path: "/api/v1/sboms/" + sbomID + "/components?limit=200"},
		{name: "sbom dependencies", path: "/api/v1/sboms/" + sbomID + "/dependencies"},
		{name: "sbom vulns", path: "/api/v1/sboms/" + sbomID + "/vulns?limit=50"},
		{name: "stats", path: "/api/v1/stats"},
		{name: "discover", path: "/api/v1/discover"},
		{name: "artifact changelog", path: "/api/v1/artifacts/" + artifactID + "/changelog"},
		{name: "artifact vulns", path: "/api/v1/artifacts/" + artifactID + "/vulns?sort=severity&dir=desc&limit=50"},
		{
			name: "component versions",
			path: "/api/v1/components/versions?name=pkg-1&limit=50",
			skip: "ocidex-7gf7.6",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skipf("unbounded until %s", tc.skip)
			}

			start := time.Now()
			resp, err := doWithAuth(t, http.MethodGet, srv.URL+tc.path, "", ownerKey)
			if err != nil {
				t.Fatalf("get %s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			elapsed := time.Since(start)

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("get %s: status %d", tc.path, resp.StatusCode)
			}
			if elapsed > latencyBudget {
				t.Fatalf("get %s took %s, over the %s budget: %d versions x %d components is a fraction of the real corpus, so this is unbounded work, not a slow machine",
					tc.path, elapsed.Round(time.Millisecond), latencyBudget, widthVersions, widthComponents)
			}
		})
	}
}

// uuidString renders a pgtype.UUID for use in a URL.
func uuidString(t *testing.T, u pgtype.UUID) string {
	t.Helper()
	s, err := u.Value()
	if err != nil {
		t.Fatalf("rendering uuid: %v", err)
	}
	str, ok := s.(string)
	if !ok {
		t.Fatalf("rendering uuid: got %T", s)
	}
	return str
}
