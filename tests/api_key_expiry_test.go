package tests

import (
	"net/http"
	"testing"
	"time"

	"github.com/matryer/is"
)

// An expired key is refused like an unknown one, and last_used_at is written
// at most once a minute however often the key is used.
func TestAPIKeyExpiryAndLastUsedThrottle(t *testing.T) {
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
	userID := seedUser(t, pool, 7951, "expiry-user", "member")

	status := func(key string) int {
		resp, err := doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/users/me", "", key)
		is.NoErr(err)
		defer resp.Body.Close()
		return resp.StatusCode
	}

	live, err := authSvc.CreateExpiringAPIKey(ctx, userID.String(), "live", nil, time.Now().Add(time.Hour))
	is.NoErr(err)
	is.Equal(status(live), http.StatusOK)

	// Expire it in place: the same key is now refused.
	_, err = pool.Exec(ctx, `UPDATE api_key SET expires_at = now() - interval '1 second' WHERE name = 'live'`)
	is.NoErr(err)
	is.Equal(status(live), http.StatusUnauthorized)

	// Throttle: after the first use stamps last_used_at, further uses within a
	// minute leave it untouched.
	never, err := authSvc.CreateAPIKey(ctx, userID.String(), "never", nil)
	is.NoErr(err)
	is.Equal(status(never), http.StatusOK)
	var first, after time.Time
	is.NoErr(pool.QueryRow(ctx, `SELECT last_used_at FROM api_key WHERE name = 'never'`).Scan(&first))
	for range 5 {
		is.Equal(status(never), http.StatusOK)
	}
	is.NoErr(pool.QueryRow(ctx, `SELECT last_used_at FROM api_key WHERE name = 'never'`).Scan(&after))
	is.True(after.Equal(first))
}
