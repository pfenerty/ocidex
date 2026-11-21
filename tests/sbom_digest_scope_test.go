package tests

import (
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// SBOM digest dedupe is per namespace: two tenants ingesting the same image
// digest each get their own SBOM, neither learns the other's id, and a cluster's
// workload matches its own namespace's SBOM, never another private one.
func TestSBOMDigestDedupeIsPerNamespace(t *testing.T) {
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
	q := repository.New(pool)

	aID := seedUser(t, pool, 7801, "digest-a", "member")
	aKey, err := authSvc.CreateAPIKey(ctx, aID, "digest-a", nil)
	is.NoErr(err)
	bID := seedUser(t, pool, 7802, "digest-b", "member")
	bKey, err := authSvc.CreateAPIKey(ctx, bID, "digest-b", nil)
	is.NoErr(err)

	aNS := seedNamespace(t, pool, "digest-a-ns", aID, "private")
	aSrc := seedSource(t, pool, aNS, "upload", "ci")
	bNS := seedNamespace(t, pool, "digest-b-ns", bID, "private")
	bSrc := seedSource(t, pool, bNS, "upload", "ci")

	// Both tenants ingest the same digest (minimalSBOM is digest('a')).
	aSBOM := mustIngest(t, srv.URL, "/api/v1/sboms?source="+aSrc, minimalSBOM, aKey)
	bSBOM := mustIngest(t, srv.URL, "/api/v1/sboms?source="+bSrc, minimalSBOM, bKey)
	is.True(aSBOM != bSBOM) // B gets its own SBOM, not A's id

	// Re-ingesting within a namespace is still idempotent.
	is.Equal(mustIngest(t, srv.URL, "/api/v1/sboms?source="+bSrc, minimalSBOM, bKey), bSBOM)
	is.Equal(mustIngest(t, srv.URL, "/api/v1/sboms?source="+aSrc, minimalSBOM, aKey), aSBOM)

	// Neither can read the other's SBOM.
	get := func(id, key string) int {
		resp, err := doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/sboms/"+id, "", key)
		is.NoErr(err)
		defer resp.Body.Close()
		return resp.StatusCode
	}
	is.Equal(get(aSBOM, bKey), http.StatusNotFound)
	is.Equal(get(bSBOM, aKey), http.StatusNotFound)

	// A's cluster runs the image. B's SBOM is newer, but it is in another
	// private namespace, so A's workload matches A's own SBOM.
	matchFor := func(nsID string, owner pgtype.UUID, name string) repository.ListClusterWorkloadsRow {
		t.Helper()
		clusterID := seedCluster(t, pool, nsID, name)
		is.NoErr(q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID:     mustUUID(t, clusterID),
			K8sNamespace:  "default",
			WorkloadKind:  "Deployment",
			WorkloadName:  "app",
			ContainerName: "app",
			ImageRef:      "docker.io/ubuntu:24.04",
			ImageDigest:   txt(digest('a')),
			PodCount:      1,
			ObservedAt:    pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
		}))
		rows, err := q.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
			ClusterID: mustUUID(t, clusterID),
			UserID:    owner,
			IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
		})
		is.NoErr(err)
		is.Equal(len(rows), 1)
		return rows[0]
	}

	aRow := matchFor(aNS, aID, "a-prod")
	is.Equal(aRow.MatchState, "exact")
	is.Equal(aRow.SbomID.String(), aSBOM)

	// A cluster in a namespace with no SBOM for the digest does not borrow a
	// private namespace's: it is a coverage gap.
	cNS := seedNamespace(t, pool, "digest-c-ns", aID, "private")
	cRow := matchFor(cNS, aID, "c-prod")
	is.Equal(cRow.MatchState, "unknown")
}
