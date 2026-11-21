package tests

import (
	"log/slog"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/service"
)

// TestClusterCredentialLifecycle pins ocidex-70eo.5 against the real schema:
// a minted credential validates as bound to its cluster with push_inventory
// alone, rotation keeps the name and kills the old key, revoke kills the new
// one, and deleting the cluster revokes whatever is left.
func TestClusterCredentialLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	clusters := service.NewClusterService(pool, nil)
	auth := service.NewAuthService(pool, &config.Config{SessionSecret: testSessionSecret}, event.NewBus(slog.Default()), nil)

	owner := seedUser(t, pool, 9020, "cred-owner", "member")
	nsID := seedNamespace(t, pool, "cred-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "prod")

	cred, err := clusters.CreateCredential(ctx, clusterID, owner, "prod-agent")
	is.NoErr(err)
	is.True(cred.Plaintext != "")

	user, err := auth.ValidateAPIKey(ctx, cred.Plaintext)
	is.NoErr(err)
	is.Equal(user.APIKeyClusterID, clusterID)
	is.Equal(len(user.APIKeyCaps), 1)
	is.Equal(string(user.APIKeyCaps[0]), "push_inventory")

	list, err := clusters.ListCredentials(ctx, clusterID)
	is.NoErr(err)
	is.Equal(len(list), 1)
	is.Equal(list[0].Name, "prod-agent")
	is.Equal(list[0].OwnerID, owner.String())

	// The owner's own key list shows it too, marked as bound.
	keys, err := auth.ListAPIKeys(ctx, owner)
	is.NoErr(err)
	is.Equal(len(keys), 1)
	is.Equal(keys[0].ClusterID, clusterID)

	rotated, err := clusters.RotateCredential(ctx, clusterID, cred.ID, owner)
	is.NoErr(err)
	is.Equal(rotated.Name, "prod-agent")
	is.True(rotated.ID != cred.ID)
	_, err = auth.ValidateAPIKey(ctx, cred.Plaintext)
	is.True(err != nil) // old key is dead
	_, err = auth.ValidateAPIKey(ctx, rotated.Plaintext)
	is.NoErr(err)

	// Rotating a credential that is no longer there is a 404, not a fresh mint.
	_, err = clusters.RotateCredential(ctx, clusterID, cred.ID, owner)
	is.Equal(err, service.ErrNotFound)

	is.NoErr(clusters.RevokeCredential(ctx, clusterID, rotated.ID))
	_, err = auth.ValidateAPIKey(ctx, rotated.Plaintext)
	is.True(err != nil)
	is.Equal(clusters.RevokeCredential(ctx, clusterID, rotated.ID), service.ErrNotFound)

	// Deleting the cluster revokes its credentials.
	last, err := clusters.CreateCredential(ctx, clusterID, owner, "last")
	is.NoErr(err)
	is.NoErr(clusters.Delete(ctx, clusterID))
	_, err = auth.ValidateAPIKey(ctx, last.Plaintext)
	is.True(err != nil)

	// The schema refuses a bound key with any other ceiling.
	other := seedCluster(t, pool, nsID, "other")
	_, err = pool.Exec(ctx, `INSERT INTO api_key (user_id, name, key_hash, prefix, capabilities, cluster_id)
		VALUES ($1, 'x', 'h2', 'p', ARRAY['ingest'], $2)`, owner, mustUUID(t, other))
	is.True(err != nil)
}

// TestClusterConnect pins ocidex-70eo.6: the cluster and its first credential
// arrive together, and a failed connect leaves neither behind.
func TestClusterConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	clusters := service.NewClusterService(pool, nil)
	auth := service.NewAuthService(pool, &config.Config{SessionSecret: testSessionSecret}, event.NewBus(slog.Default()), nil)

	owner := seedUser(t, pool, 9040, "connect-owner", "member")
	nsID := seedNamespace(t, pool, "connect-ns", owner, "private")

	c, cred, err := clusters.Connect(ctx, service.ConnectClusterParams{
		NamespaceID: nsID, Name: "prod", Owner: owner, AutoIngest: false,
	})
	is.NoErr(err)
	is.Equal(c.AutoIngest, false)
	is.Equal(cred.Name, "prod-agent")
	user, err := auth.ValidateAPIKey(ctx, cred.Plaintext)
	is.NoErr(err)
	is.Equal(user.APIKeyClusterID, c.ID)

	// Same name again: the conflict rolls the whole connect back.
	var before int
	is.NoErr(pool.QueryRow(ctx, `SELECT count(*) FROM api_key`).Scan(&before))
	_, _, err = clusters.Connect(ctx, service.ConnectClusterParams{
		NamespaceID: nsID, Name: "prod", Owner: owner, AutoIngest: true,
	})
	is.Equal(err, service.ErrConflict)
	var after int
	is.NoErr(pool.QueryRow(ctx, `SELECT count(*) FROM api_key`).Scan(&after))
	is.Equal(after, before)
}
