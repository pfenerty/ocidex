package tests

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/service"
)

// TestWorkloadsForArtifact pins ocidex-70eo.8: an artifact's page can say where
// it runs, by exact and index digest, and a private cluster stays invisible to
// someone who cannot see its namespace.
func TestWorkloadsForArtifact(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	svc := service.NewClusterService(pool, nil)
	q := repository.New(pool)

	owner := seedUser(t, pool, 9050, "art-owner", "member")
	outsider := seedUser(t, pool, 9051, "art-outsider", "member")
	nsID := seedNamespace(t, pool, "art-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "prod")
	artifactID := seedArtifactSBOM(t, pool, nsID, "ghcr.io/x/api", digest('a'), digest('b'))
	seedArtifactSBOM(t, pool, nsID, "ghcr.io/x/other", digest('c'), "")

	observed := pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	for _, w := range []struct{ name, dgst string }{{"exact", digest('a')}, {"index", digest('b')}, {"other", digest('c')}} {
		is.NoErr(q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID: mustUUID(t, clusterID), K8sNamespace: "apps", WorkloadKind: "Deployment",
			WorkloadName: w.name, ContainerName: "c", ImageRef: "ghcr.io/x/api:1",
			ImageDigest: txt(w.dgst), PodCount: 1, ObservedAt: observed,
		}))
	}

	rows, err := svc.WorkloadsForArtifact(ctx, artifactID, 50, service.VisibilityFilter{UserID: owner})
	is.NoErr(err)
	is.Equal(len(rows), 2)
	states := map[string]string{}
	for _, r := range rows {
		states[r.WorkloadName] = r.MatchState
		is.Equal(r.ClusterName, "prod")
	}
	is.Equal(states["exact"], service.MatchExact)
	is.Equal(states["index"], service.MatchIndex)

	rows, err = svc.WorkloadsForArtifact(ctx, artifactID, 50, service.VisibilityFilter{UserID: outsider})
	is.NoErr(err)
	is.Equal(len(rows), 0)
}
