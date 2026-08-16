package tests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
	"github.com/pressly/goose/v3"

	"github.com/pfenerty/ocidex/db"
)

// The watchlist is self-scoped in *whose* it is but not in *what* may go on it:
// the artifact only has to be visible to the caller, and somebody else's public
// artifact qualifies. That asymmetry against the /users/me/* collections
// (ocidex-998g.2, which exclude others' public rows outright) is the thing
// worth pinning, so every case here seeds a second tenant with one public and
// one private namespace (ocidex-998g.3).

// artifactIDForSource reads the artifact an ingest resolved to, straight from
// the database. Going through the API would not work for the private fixture:
// the whole point of it is that the watcher cannot see it, and resolving it
// with the owner's key instead would only prove the owner's view.
func artifactIDForSource(t *testing.T, pool *pgxpool.Pool, sourceID string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(t.Context(),
		`SELECT a.id::text FROM artifact a
		 JOIN sbom s ON s.artifact_id = a.id
		 WHERE s.source_id = $1::uuid LIMIT 1`, sourceID).Scan(&id)
	if err != nil {
		t.Fatalf("resolving artifact for source %s: %v", sourceID, err)
	}
	return id
}

// watchIDs GETs the caller's watchlist and returns the artifact ids on it.
func watchIDs(t *testing.T, baseURL, apiKey string) []string {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/users/me/watches", "", apiKey)
	if err != nil {
		t.Fatalf("listing watches: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing watches: status %d", resp.StatusCode)
	}
	var body struct {
		Data []struct {
			ArtifactID string `json:"artifactId"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding watches: %v", err)
	}
	out := make([]string, 0, len(body.Data))
	for _, w := range body.Data {
		out = append(out, w.ArtifactID)
	}
	return out
}

// artifactWatched reads the watched flag off the artifact detail response,
// which is where the star gets its initial state.
func artifactWatched(t *testing.T, baseURL, apiKey, artifactID string) bool {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/artifacts/"+artifactID, "", apiKey)
	if err != nil {
		t.Fatalf("getting artifact: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("getting artifact: status %d", resp.StatusCode)
	}
	var body struct {
		Watched bool `json:"watched"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding artifact: %v", err)
	}
	return body.Watched
}

// TestArtifactWatchMigrationRollsBack exercises the down half of 00058, which
// nothing else in the suite would: every other test only ever migrates up, so a
// broken Down statement ships unnoticed until somebody actually needs to roll
// back — which is precisely the moment they cannot afford to find out.
func TestArtifactWatchMigrationRollsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	connStr, dropDB := newTestDB(t)
	defer dropDB()
	migrateDB(t, connStr)

	sqlDB, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("opening migration connection: %v", err)
	}
	defer sqlDB.Close()

	goose.SetBaseFS(db.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("setting dialect: %v", err)
	}

	tableExists := func() bool {
		var exists bool
		if err := sqlDB.QueryRow(
			`SELECT to_regclass('public.artifact_watch') IS NOT NULL`).Scan(&exists); err != nil {
			t.Fatalf("checking artifact_watch: %v", err)
		}
		return exists
	}

	is := is.New(t)
	is.True(tableExists())

	if err := goose.Down(sqlDB, "migrations"); err != nil {
		t.Fatalf("rolling back: %v", err)
	}
	is.Equal(tableExists(), false)

	if err := goose.Up(sqlDB, "migrations"); err != nil {
		t.Fatalf("re-applying: %v", err)
	}
	is.True(tableExists())
}

func TestArtifactWatchlist(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	watcherID := seedUser(t, pool, 7601, "watch-watcher", "member")
	watcherKey, err := authSvc.CreateAPIKey(t.Context(), watcherID, "watcher", "read-write")
	is.NoErr(err)
	otherID := seedUser(t, pool, 7602, "watch-other", "member")
	otherKey, err := authSvc.CreateAPIKey(t.Context(), otherID, "other", "read-write")
	is.NoErr(err)

	// The other tenant owns both artifacts. The watcher owns neither, which is
	// the whole point: one is public and watchable, the other is not.
	publicNS := seedNamespace(t, pool, "watch-public-ns", otherID, "public")
	publicSrc := seedSource(t, pool, publicNS, "upload", "watch-public-src")
	mustIngest(t, srv.URL, "/api/v1/sboms?source="+publicSrc, minimalSBOM, otherKey)

	privateNS := seedNamespace(t, pool, "watch-private-ns", otherID, "private")
	privateSrc := seedSource(t, pool, privateNS, "upload", "watch-private-src")
	mustIngest(t, srv.URL, "/api/v1/sboms?source="+privateSrc, alpineSBOM, otherKey)

	publicArtifact := artifactIDForSource(t, pool, publicSrc)
	privateArtifact := artifactIDForSource(t, pool, privateSrc)
	is.True(publicArtifact != privateArtifact)

	t.Run("watches a public artifact it does not own", func(t *testing.T) {
		is := is.New(t)
		resp, err := doWithAuth(t, http.MethodPut, srv.URL+"/api/v1/users/me/watches/"+publicArtifact, "", watcherKey)
		is.NoErr(err)
		resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusNoContent)

		is.Equal(watchIDs(t, srv.URL, watcherKey), []string{publicArtifact})
		// The star's initial state survives a reload because it rides on the
		// detail response rather than living only in the client.
		is.True(artifactWatched(t, srv.URL, watcherKey, publicArtifact))
	})

	t.Run("watching twice is idempotent", func(t *testing.T) {
		is := is.New(t)
		resp, err := doWithAuth(t, http.MethodPut, srv.URL+"/api/v1/users/me/watches/"+publicArtifact, "", watcherKey)
		is.NoErr(err)
		resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusNoContent)
		is.Equal(len(watchIDs(t, srv.URL, watcherKey)), 1)
	})

	t.Run("cannot watch an artifact it cannot see", func(t *testing.T) {
		is := is.New(t)
		resp, err := doWithAuth(t, http.MethodPut, srv.URL+"/api/v1/users/me/watches/"+privateArtifact, "", watcherKey)
		is.NoErr(err)
		resp.Body.Close()
		// 404, not 403: a 403 would confirm the artifact exists, which is
		// exactly what the visibility rule is hiding.
		is.Equal(resp.StatusCode, http.StatusNotFound)
		is.Equal(watchIDs(t, srv.URL, watcherKey), []string{publicArtifact})
	})

	t.Run("watchlist is self-scoped", func(t *testing.T) {
		is := is.New(t)
		// The owner of the very artifact the watcher starred sees an empty
		// list: a watch belongs to the watcher, not to the artifact.
		is.Equal(len(watchIDs(t, srv.URL, otherKey)), 0)
		is.Equal(artifactWatched(t, srv.URL, otherKey, publicArtifact), false)
	})

	t.Run("unwatch removes it, and is idempotent", func(t *testing.T) {
		is := is.New(t)
		for range 2 {
			resp, err := doWithAuth(t, http.MethodDelete, srv.URL+"/api/v1/users/me/watches/"+publicArtifact, "", watcherKey)
			is.NoErr(err)
			resp.Body.Close()
			is.Equal(resp.StatusCode, http.StatusNoContent)
		}
		is.Equal(len(watchIDs(t, srv.URL, watcherKey)), 0)
		is.Equal(artifactWatched(t, srv.URL, watcherKey, publicArtifact), false)
	})

	t.Run("anonymous callers are rejected", func(t *testing.T) {
		is := is.New(t)
		for _, req := range [][2]string{
			{http.MethodGet, "/api/v1/users/me/watches"},
			{http.MethodPut, "/api/v1/users/me/watches/" + publicArtifact},
			{http.MethodDelete, "/api/v1/users/me/watches/" + publicArtifact},
		} {
			resp, err := doWithAuth(t, req[0], srv.URL+req[1], "", "")
			is.NoErr(err)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s anonymous: got %d, want 401", req[0], req[1], resp.StatusCode)
			}
		}
	})
}
