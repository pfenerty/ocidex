package tests

import (
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// TestClusterPushHistoryAndHealth pins ocidex-70eo.4 against the real schema:
// a rejection makes the cluster erroring with its reason, an accepted push
// clears that, the history is capped, and an unknown cluster records nothing.
func TestClusterPushHistoryAndHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	svc := service.NewClusterService(pool, nil)

	owner := seedUser(t, pool, 9030, "health-owner", "member")
	nsID := seedNamespace(t, pool, "health-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "prod")

	c, err := svc.Get(ctx, clusterID)
	is.NoErr(err)
	is.Equal(c.Health(time.Now()).State, service.HealthNeverReported)

	is.NoErr(svc.RecordPush(ctx, clusterID, service.PushAttempt{Status: 401, Reason: "bad key"}))
	c, err = svc.Get(ctx, clusterID)
	is.NoErr(err)
	h := c.Health(time.Now())
	is.Equal(h.State, service.HealthErroring)
	is.Equal(h.Reason, "bad key")

	// An accepted snapshot is newer than the rejection: healthy again.
	time.Sleep(10 * time.Millisecond)
	_, err = svc.ReplaceInventory(ctx, clusterID, nil, nil)
	is.NoErr(err)
	n := int32(0)
	is.NoErr(svc.RecordPush(ctx, clusterID, service.PushAttempt{Accepted: true, Status: 200, Workloads: &n}))
	c, err = svc.Get(ctx, clusterID)
	is.NoErr(err)
	is.Equal(c.Health(time.Now()).State, service.HealthHealthy)

	pushes, err := svc.ListPushes(ctx, clusterID, 10)
	is.NoErr(err)
	is.Equal(len(pushes), 2)
	is.True(pushes[0].Accepted) // newest first
	is.Equal(pushes[1].Reason, "bad key")

	// Capped at 50 per cluster, however many arrive.
	for range 60 {
		is.NoErr(svc.RecordPush(ctx, clusterID, service.PushAttempt{Status: 401, Reason: "spam"}))
	}
	var count int
	is.NoErr(pool.QueryRow(ctx, `SELECT count(*) FROM cluster_push WHERE cluster_id = $1`, mustUUID(t, clusterID)).Scan(&count))
	is.Equal(count, 50)

	// A push to an id that is no cluster leaves no trace and no error.
	is.NoErr(svc.RecordPush(ctx, "00000000-0000-0000-0000-000000000000", service.PushAttempt{Status: 401, Reason: "x"}))
}

// TestClusterPushFloodKeepsHistory: a flood of unauthenticated rejections
// for a known cluster id folds into one history row, so the genuine agent's
// last push stays visible.
func TestClusterPushFloodKeepsHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	svc := service.NewClusterService(pool, nil)

	owner := seedUser(t, pool, 9032, "flood-owner", "member")
	nsID := seedNamespace(t, pool, "flood-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "prod")

	// The genuine agent: one failure it caused, then an accepted push.
	is.NoErr(svc.RecordPush(ctx, clusterID, service.PushAttempt{Status: 422, Reason: "snapshot failed validation"}))
	n := int32(3)
	is.NoErr(svc.RecordPush(ctx, clusterID, service.PushAttempt{Accepted: true, Status: 200, Workloads: &n, AgentVersion: "v1"}))

	const anon = "The agent's API key was not accepted: it was revoked, rotated or mistyped."
	for range 1000 {
		is.NoErr(svc.RecordPush(ctx, clusterID, service.PushAttempt{Status: 401, Reason: anon, Unauthenticated: true}))
	}

	pushes, err := svc.ListPushes(ctx, clusterID, 50)
	is.NoErr(err)
	is.Equal(len(pushes), 3) // one folded anonymous row, then both genuine ones
	is.Equal(pushes[0].Reason, anon)
	is.True(pushes[1].Accepted)
	is.Equal(pushes[1].AgentVersion, "v1")
	is.Equal(pushes[2].Reason, "snapshot failed validation")

	// The rejection still reaches the cluster's health, as a revoked key must.
	c, err := svc.Get(ctx, clusterID)
	is.NoErr(err)
	is.Equal(c.Health(time.Now()).State, service.HealthErroring)

	// A genuine push breaks the run; the next anonymous rejection is a new row.
	is.NoErr(svc.RecordPush(ctx, clusterID, service.PushAttempt{Accepted: true, Status: 200, Workloads: &n}))
	is.NoErr(svc.RecordPush(ctx, clusterID, service.PushAttempt{Status: 401, Reason: anon, Unauthenticated: true}))
	pushes, err = svc.ListPushes(ctx, clusterID, 50)
	is.NoErr(err)
	is.Equal(len(pushes), 5)
}

// TestClusterPauseAndResume pins ocidex-70eo.9: pausing is reported as its own
// state, and resuming clears the refusals the pause itself caused.
func TestClusterPauseAndResume(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	svc := service.NewClusterService(pool, nil)

	owner := seedUser(t, pool, 9031, "pause-owner", "member")
	nsID := seedNamespace(t, pool, "pause-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "prod")

	yes, no := true, false
	c, err := svc.Update(ctx, service.UpdateClusterParams{ID: clusterID, Name: "prod", Paused: &yes})
	is.NoErr(err)
	is.True(c.PausedAt != nil)
	is.Equal(c.Health(time.Now()).State, service.HealthPaused)

	// A push refused while paused.
	is.NoErr(svc.RecordPush(ctx, clusterID, service.PushAttempt{Status: 409, Reason: "paused"}))

	// A rename leaves the pause alone.
	c, err = svc.Update(ctx, service.UpdateClusterParams{ID: clusterID, Name: "prod-2"})
	is.NoErr(err)
	is.True(c.PausedAt != nil)

	c, err = svc.Update(ctx, service.UpdateClusterParams{ID: clusterID, Name: "prod-2", Paused: &no})
	is.NoErr(err)
	is.True(c.PausedAt == nil)
	is.Equal(c.LastPushError, "")
	is.Equal(c.Health(time.Now()).State, service.HealthNeverReported)
}
