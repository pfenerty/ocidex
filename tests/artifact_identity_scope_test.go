package tests

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
)

// withSubjectPurl sets metadata.component.purl on one of the ubuntu fixtures.
func withSubjectPurl(sbom, purl string) string {
	return strings.Replace(sbom, `"version": "24.04",`, `"version": "24.04", "purl": "`+purl+`",`, 1)
}

func artifactPurl(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var purl *string
	if err := pool.QueryRow(t.Context(), `SELECT purl FROM artifact WHERE id = $1`, id).Scan(&purl); err != nil {
		t.Fatalf("artifact %s purl: %v", id, err)
	}
	if purl == nil {
		return ""
	}
	return *purl
}

// The artifact row is shared by name, so only a namespace that already holds it
// may change its purl/cpe. Another tenant ingesting the same name with a
// different purl leaves it as it was.
func TestSharedArtifactIdentityIsNotRewrittenByAnotherNamespace(t *testing.T) {
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

	aID := seedUser(t, pool, 7901, "ident-a", "member")
	aKey, err := authSvc.CreateAPIKey(ctx, aID.String(), "ident-a", nil)
	is.NoErr(err)
	bID := seedUser(t, pool, 7902, "ident-b", "member")
	bKey, err := authSvc.CreateAPIKey(ctx, bID.String(), "ident-b", nil)
	is.NoErr(err)

	aNS := seedNamespace(t, pool, "ident-a-ns", aID, "private")
	aSrc := seedSource(t, pool, aNS, "upload", "ci")
	bNS := seedNamespace(t, pool, "ident-b-ns", bID, "private")
	bSrc := seedSource(t, pool, bNS, "upload", "ci")

	const aPurl = "pkg:oci/ubuntu@24.04?repository_url=docker.io/library/ubuntu"
	aSBOM := mustIngest(t, srv.URL, "/api/v1/sboms?source="+aSrc, withSubjectPurl(minimalSBOM, aPurl), aKey)
	artifact := artifactIDForSBOM(t, pool, aSBOM)
	is.Equal(artifactPurl(t, pool, artifact), aPurl)

	// B shares the name but not the artifact's history: its purl is ignored.
	bSBOM := mustIngest(t, srv.URL, "/api/v1/sboms?source="+bSrc,
		withSubjectPurl(twinSBOM, "pkg:oci/evil@1?repository_url=evil.example/ubuntu"), bKey)
	is.Equal(artifactIDForSBOM(t, pool, bSBOM), artifact)
	is.Equal(artifactPurl(t, pool, artifact), aPurl)
}
