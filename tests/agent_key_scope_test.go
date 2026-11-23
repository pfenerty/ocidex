package tests

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// TestAgentKeyScopedToNamespaces is ADR-0058 A2 through real SQL. alice owns two
// private namespaces, each with one artifact. An agent key limited to the first
// sees that artifact and public data, and nothing of the second: not in the
// list, not by id, not in search counts. Her unscoped personal key sees both.
func TestAgentKeyScopedToNamespaces(t *testing.T) {
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

	alice := seedUser(t, pool, 9701, "scope-alice", "member")
	nsA := seedNamespace(t, pool, "scope-a", alice, "private")
	nsB := seedNamespace(t, pool, "scope-b", alice, "private")
	personal, err := authSvc.CreateAPIKey(ctx, alice.String(), "personal", nil)
	is.NoErr(err)

	ingest := func(nsID, body string) {
		t.Helper()
		resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms?source="+seedSource(t, pool, nsID, "upload", "ci"), body, personal)
		is.NoErr(err)
		is.Equal(resp.StatusCode, http.StatusCreated)
		resp.Body.Close()
	}
	ingest(nsA, minimalSBOM) // docker.io/ubuntu
	ingest(nsB, alpineSBOM)  // docker.io/alpine
	refreshRollups(t, pool)

	agent, err := authSvc.CreateKey(ctx, alice.String(), service.KeySpec{
		Name: "agent", Kind: service.KeyKindAgent, Namespaces: []string{nsA}, AgentLabel: "test agent",
	})
	is.NoErr(err)

	sorted := func(s []string) []string { sort.Strings(s); return s }
	is.Equal(sorted(artifactNames(t, srv.URL, personal)), []string{"docker.io/alpine", "docker.io/ubuntu"})
	is.Equal(artifactNames(t, srv.URL, agent), []string{"docker.io/ubuntu"})

	// By id: the out-of-scope artifact is not found, not forbidden, so the key
	// cannot probe what exists outside its namespaces.
	var alpineID string
	is.NoErr(pool.QueryRow(ctx, `SELECT id::text FROM artifact WHERE name = 'docker.io/alpine'`).Scan(&alpineID))
	resp, err := doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/artifacts/"+alpineID, "", agent)
	is.NoErr(err)
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusNotFound)

	// Rollup-backed reads narrow too: components from the other namespace are
	// invisible to the scoped key.
	is.True(componentCount(t, srv.URL, personal, "musl") > 0)
	is.Equal(componentCount(t, srv.URL, agent, "musl"), 0)

	// Writes: the agent key cannot ingest into the other namespace.
	resp, err = doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms?source="+seedSource(t, pool, nsB, "upload", "agent"),
		strings.Replace(alpineSBOM, "4444-444444444444", "4444-444444444445", 1), agent)
	is.NoErr(err)
	resp.Body.Close()
	is.True(resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound)
}

// TestAgentKeyCreationRules pins what a key may be limited to.
func TestAgentKeyCreationRules(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	_, authSvc := setupServerWithAuth(t, pool)
	is := is.New(t)
	ctx := t.Context()

	alice := seedUser(t, pool, 9711, "rules-alice", "member")
	bob := seedUser(t, pool, 9712, "rules-bob", "member")
	mine := seedNamespace(t, pool, "rules-mine", alice, "private")
	theirs := seedNamespace(t, pool, "rules-theirs", bob, "private")

	// An agent key must be limited to at least one namespace.
	_, err := authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "a", Kind: service.KeyKindAgent})
	is.True(err != nil)

	// A key cannot be limited to a namespace its holder does not belong to.
	_, err = authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "b", Kind: service.KeyKindAgent, Namespaces: []string{theirs}})
	is.True(err != nil)

	// A key cannot be a cluster key from here.
	_, err = authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "c", Kind: service.KeyKindCluster, Namespaces: []string{mine}})
	is.True(err != nil)

	// The listing reports kind, namespaces and label.
	_, err = authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "ok", Kind: service.KeyKindAgent, Namespaces: []string{mine}, AgentLabel: "laptop"})
	is.NoErr(err)
	keys, err := authSvc.ListAPIKeys(ctx, alice.String())
	is.NoErr(err)
	is.Equal(len(keys), 1)
	is.Equal(keys[0].Kind, service.KeyKindAgent)
	is.Equal(keys[0].Namespaces, []string{mine})
	is.Equal(keys[0].AgentLabel, "laptop")

	// The validated identity carries the scope.
	plain, err := authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "ok2", Kind: service.KeyKindAgent, Namespaces: []string{mine}})
	is.NoErr(err)
	u, err := authSvc.ValidateAPIKey(ctx, plain)
	is.NoErr(err)
	is.Equal(u.APIKeyKind, service.KeyKindAgent)
	is.Equal(u.APIKeyNamespaces, []string{mine})
}
