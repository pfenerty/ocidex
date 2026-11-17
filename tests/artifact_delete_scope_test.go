package tests

import (
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
)

// The artifact row is shared by name across namespaces, so deleting it is
// confined to the caller's namespaces: another tenant's SBOMs of the same
// artifact survive, and the artifact row goes only with its last namespace.
func TestDeleteSharedArtifactIsConfinedToCallerNamespaces(t *testing.T) {
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

	aID := seedUser(t, pool, 7701, "tenant-a", "member")
	aKey, err := authSvc.CreateAPIKey(ctx, aID, "tenant-a", nil)
	is.NoErr(err)
	bID := seedUser(t, pool, 7702, "tenant-b", "member")
	bKey, err := authSvc.CreateAPIKey(ctx, bID, "tenant-b", nil)
	is.NoErr(err)

	aNS := seedNamespace(t, pool, "tenant-a-ns", aID, "private")
	aSrc := seedSource(t, pool, aNS, "upload", "ci")
	aSBOM := mustIngest(t, srv.URL, "/api/v1/sboms?source="+aSrc, minimalSBOM, aKey)

	// Tenant B ingests the same artifact name, so the artifact now hangs from
	// both namespaces.
	bNS := seedNamespace(t, pool, "tenant-b-ns", bID, "private")
	bSrc := seedSource(t, pool, bNS, "upload", "ci")
	bSBOM := mustIngest(t, srv.URL, "/api/v1/sboms?source="+bSrc, twinSBOM, bKey)

	artifact := artifactIDForSBOM(t, pool, aSBOM)
	is.Equal(artifactIDForSBOM(t, pool, bSBOM), artifact) // one shared artifact row
	is.Equal(artifactNamespaceCount(t, pool, artifact), 2)

	deleteArtifact := func(key string) int {
		resp, err := doWithAuth(t, http.MethodDelete, srv.URL+"/api/v1/artifacts/"+artifact, "", key)
		is.NoErr(err)
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// B's delete removes only B's SBOM and B's link.
	is.Equal(deleteArtifact(bKey), http.StatusNoContent)
	is.True(sbomExists(t, pool, aSBOM))
	is.True(!sbomExists(t, pool, bSBOM))
	is.True(artifactExists(t, pool, artifact))
	is.Equal(artifactNamespaceCount(t, pool, artifact), 1)

	// B no longer holds the artifact anywhere, so a second delete is refused.
	is.Equal(deleteArtifact(bKey), http.StatusForbidden)
	is.True(sbomExists(t, pool, aSBOM))

	// A's delete removes the last namespace, and the artifact row with it.
	is.Equal(deleteArtifact(aKey), http.StatusNoContent)
	is.True(!sbomExists(t, pool, aSBOM))
	is.True(!artifactExists(t, pool, artifact))
}

func sbomExists(t *testing.T, pool *pgxpool.Pool, id string) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS (SELECT 1 FROM sbom WHERE id = $1)`, id).Scan(&ok); err != nil {
		t.Fatalf("sbom %s exists: %v", id, err)
	}
	return ok
}

func artifactExists(t *testing.T, pool *pgxpool.Pool, id string) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS (SELECT 1 FROM artifact WHERE id = $1)`, id).Scan(&ok); err != nil {
		t.Fatalf("artifact %s exists: %v", id, err)
	}
	return ok
}

func artifactNamespaceCount(t *testing.T, pool *pgxpool.Pool, id string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM artifact_namespace WHERE artifact_id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("artifact %s namespaces: %v", id, err)
	}
	return n
}
