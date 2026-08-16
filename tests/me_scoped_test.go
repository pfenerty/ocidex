package tests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/matryer/is"
)

// The /api/v1/users/me/* collections select on ownership, not visibility. That
// is the one thing about them that can be got wrong, and it is invisible in a
// single-tenant fixture: with only the caller's own data present, the ownership
// path and the visibility path return the same rows.
//
// So every case here seeds a *second* tenant whose namespace is public. The
// sibling list endpoints must show that tenant's rows; the me-scoped ones must
// not. An admin is included for the other half of the rule — admin widens the
// visibility path and must not widen this one (ocidex-998g.2).

// meFeedNames GETs a me-scoped collection and returns the value of `field` from
// every row, so a test can assert on which rows came back rather than only how
// many.
func meFeedNames(t *testing.T, baseURL, path, apiKey, field string) []string {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+path, "", apiKey)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", path, resp.StatusCode)
	}
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	out := make([]string, 0, len(body.Data))
	for _, row := range body.Data {
		v, ok := row[field].(string)
		if !ok {
			t.Fatalf("GET %s: row has no string %q field: %v", path, field, row)
		}
		out = append(out, v)
	}
	return out
}

func TestMeScopedCollectionsExcludeOthersPublicRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7501, "me-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", "read-write")
	is.NoErr(err)
	otherID := seedUser(t, pool, 7502, "me-other", "member")
	otherKey, err := authSvc.CreateAPIKey(t.Context(), otherID, "other", "read-write")
	is.NoErr(err)
	adminID := seedUser(t, pool, 7503, "me-admin", "admin")
	adminKey, err := authSvc.CreateAPIKey(t.Context(), adminID, "admin", "read-write")
	is.NoErr(err)

	// Tenant one: private, owned by ownerID.
	mineNS := seedNamespace(t, pool, "mine-ns", ownerID, "private")
	mineSrc := seedSource(t, pool, mineNS, "upload", "mine-src")
	seedRegistryInNamespace(t, pool, mineNS, "mine-reg")
	mustIngest(t, srv.URL, "/api/v1/sboms?source="+mineSrc, minimalSBOM, ownerKey)

	// Tenant two: public, owned by otherID. Everything below turns on these
	// rows being visible to everyone and owned by nobody but otherID.
	theirsNS := seedNamespace(t, pool, "theirs-ns", otherID, "public")
	theirsSrc := seedSource(t, pool, theirsNS, "upload", "theirs-src")
	seedRegistryInNamespace(t, pool, theirsNS, "theirs-reg")
	mustIngest(t, srv.URL, "/api/v1/sboms?source="+theirsSrc, alpineSBOM, otherKey)

	t.Run("namespaces", func(t *testing.T) {
		is := is.New(t)
		// The sibling endpoint includes the other tenant's public namespace...
		is.Equal(len(meFeedNames(t, srv.URL, "/api/v1/namespaces", ownerKey, "name")), 2)
		// ...and the me-scoped one does not.
		is.Equal(meFeedNames(t, srv.URL, "/api/v1/users/me/namespaces", ownerKey, "name"),
			[]string{"mine-ns"})
		is.Equal(meFeedNames(t, srv.URL, "/api/v1/users/me/namespaces", otherKey, "name"),
			[]string{"theirs-ns"})
		// An admin sees both from /namespaces but owns neither.
		is.Equal(len(meFeedNames(t, srv.URL, "/api/v1/namespaces", adminKey, "name")), 2)
		is.Equal(len(meFeedNames(t, srv.URL, "/api/v1/users/me/namespaces", adminKey, "name")), 0)
	})

	t.Run("sources", func(t *testing.T) {
		is := is.New(t)
		is.Equal(len(meFeedNames(t, srv.URL, "/api/v1/sources", ownerKey, "name")), 4)
		is.Equal(meFeedNames(t, srv.URL, "/api/v1/users/me/sources", ownerKey, "name"),
			[]string{"mine-src", "mine-reg"})
		is.Equal(meFeedNames(t, srv.URL, "/api/v1/users/me/sources", otherKey, "name"),
			[]string{"theirs-src", "theirs-reg"})
		is.Equal(len(meFeedNames(t, srv.URL, "/api/v1/users/me/sources", adminKey, "name")), 0)
	})

	t.Run("registries", func(t *testing.T) {
		is := is.New(t)
		is.Equal(len(meFeedNames(t, srv.URL, "/api/v1/registries", ownerKey, "name")), 2)
		is.Equal(meFeedNames(t, srv.URL, "/api/v1/users/me/registries", ownerKey, "name"),
			[]string{"mine-reg"})
		is.Equal(meFeedNames(t, srv.URL, "/api/v1/users/me/registries", otherKey, "name"),
			[]string{"theirs-reg"})
		is.Equal(len(meFeedNames(t, srv.URL, "/api/v1/users/me/registries", adminKey, "name")), 0)
	})

	t.Run("artifacts", func(t *testing.T) {
		is := is.New(t)
		// sufficient=false because a freshly uploaded SBOM has not been
		// enriched, and the default filter hides unenriched artifacts.
		const q = "?sufficient=false"
		all := meFeedNames(t, srv.URL, "/api/v1/artifacts"+q, ownerKey, "name")
		is.Equal(len(all), 2)
		mine := meFeedNames(t, srv.URL, "/api/v1/users/me/artifacts"+q, ownerKey, "name")
		is.Equal(len(mine), 1)
		theirs := meFeedNames(t, srv.URL, "/api/v1/users/me/artifacts"+q, otherKey, "name")
		is.Equal(len(theirs), 1)
		// The two tenants' artifacts are different rows, which is what makes
		// the counts above meaningful.
		is.True(mine[0] != theirs[0])
		is.Equal(len(meFeedNames(t, srv.URL, "/api/v1/users/me/artifacts"+q, adminKey, "name")), 0)
	})

	t.Run("activity", func(t *testing.T) {
		is := is.New(t)
		is.Equal(meFeedNames(t, srv.URL, "/api/v1/users/me/activity", ownerKey, "namespaceName"),
			[]string{"mine-ns"})
		is.Equal(meFeedNames(t, srv.URL, "/api/v1/users/me/activity", otherKey, "namespaceName"),
			[]string{"theirs-ns"})
		is.Equal(len(meFeedNames(t, srv.URL, "/api/v1/users/me/activity", adminKey, "namespaceName")), 0)
	})
}

// TestMeScopedCollectionsRequireAuth pins the auth class declared in
// authclass.go: these are authenticated-class, so an anonymous caller gets 401
// rather than an empty list.
func TestMeScopedCollectionsRequireAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, _ := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	for _, path := range []string{
		"/api/v1/users/me/namespaces",
		"/api/v1/users/me/sources",
		"/api/v1/users/me/registries",
		"/api/v1/users/me/artifacts",
		"/api/v1/users/me/activity",
	} {
		resp, err := doWithAuth(t, http.MethodGet, srv.URL+path, "", "")
		is.NoErr(err)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s anonymous: got %d, want 401", path, resp.StatusCode)
		}
	}
}
