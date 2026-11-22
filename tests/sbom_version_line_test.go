package tests

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// TestSBOMVersionLineColumns holds sbom.version_variant and
// sbom.version_prerelease to the golden cases the Go and web helpers are tested
// against, so the three implementations of the rule cannot drift.
func TestSBOMVersionLineColumns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	ctx := t.Context()

	raw, err := os.ReadFile("../web/src/utils/versionLine.golden.json")
	is.NoErr(err)
	var cases []struct {
		Version    string `json:"version"`
		Variant    string `json:"variant"`
		Prerelease bool   `json:"prerelease"`
	}
	is.NoErr(json.Unmarshal(raw, &cases))

	ownerID := seedUser(t, pool, 8601, "version-line", "member")
	nsID := seedNamespace(t, pool, "version-line", ownerID, "public")
	var artifactID string
	is.NoErr(pool.QueryRow(ctx,
		`INSERT INTO artifact (type, name) VALUES ('container', 'version-line') RETURNING id::text`).Scan(&artifactID))

	for _, c := range cases {
		var variant string
		var prerelease bool
		// The empty golden version is stored as NULL, which is how a subject
		// without a version arrives.
		is.NoErr(pool.QueryRow(ctx, `
			INSERT INTO sbom (spec_version, raw_bom, artifact_id, namespace_id, subject_version)
			VALUES ('1.6', '{}'::jsonb, $1::uuid, $2::uuid, NULLIF($3, ''))
			RETURNING version_variant, version_prerelease
		`, artifactID, nsID, c.Version).Scan(&variant, &prerelease))
		goVariant, goPrerelease := service.VersionLine(c.Version)
		if variant != c.Variant || prerelease != c.Prerelease || goVariant != variant || goPrerelease != prerelease {
			t.Errorf("%q: columns (%q, %v), service.VersionLine (%q, %v), golden (%q, %v)",
				c.Version, variant, prerelease, goVariant, goPrerelease, c.Variant, c.Prerelease)
		}
	}
}
