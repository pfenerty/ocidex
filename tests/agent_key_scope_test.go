package tests

import (
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/authz"
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
		Name: "agent", Kind: service.KeyKindAgent, Preset: "analyst", Namespaces: []string{nsA}, AgentLabel: "test agent",
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
	_, err := authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "a", Kind: service.KeyKindAgent, Preset: "analyst"})
	is.True(err != nil)

	// A key cannot be limited to a namespace its holder does not belong to.
	_, err = authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "b", Kind: service.KeyKindAgent, Preset: "analyst", Namespaces: []string{theirs}})
	is.True(err != nil)

	// A key cannot be a cluster key from here.
	_, err = authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "c", Kind: service.KeyKindCluster, Namespaces: []string{mine}})
	is.True(err != nil)

	// The listing reports kind, namespaces and label.
	_, err = authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "ok", Kind: service.KeyKindAgent, Preset: "analyst", Namespaces: []string{mine}, AgentLabel: "laptop"})
	is.NoErr(err)
	keys, err := authSvc.ListAPIKeys(ctx, alice.String())
	is.NoErr(err)
	is.Equal(len(keys), 1)
	is.Equal(keys[0].Kind, service.KeyKindAgent)
	is.Equal(keys[0].Namespaces, []string{mine})
	is.Equal(keys[0].AgentLabel, "laptop")

	// The validated identity carries the scope.
	plain, err := authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "ok2", Kind: service.KeyKindAgent, Preset: "analyst", Namespaces: []string{mine}})
	is.NoErr(err)
	u, err := authSvc.ValidateAPIKey(ctx, plain)
	is.NoErr(err)
	is.Equal(u.APIKeyKind, service.KeyKindAgent)
	is.Equal(u.APIKeyNamespaces, []string{mine})
}

// TestAgentKeyPresetsAndLimits pins ADR-0058 A3 and A7 for key creation and
// key management.
func TestAgentKeyPresetsAndLimits(t *testing.T) {
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

	alice := seedUser(t, pool, 9721, "preset-alice", "member")
	ns := seedNamespace(t, pool, "preset-ns", alice, "private")
	agent := func(spec service.KeySpec) (string, error) {
		spec.Name, spec.Kind, spec.Namespaces = "a", service.KeyKindAgent, []string{ns}
		return authSvc.CreateKey(ctx, alice.String(), spec)
	}

	// No preset and no capabilities would mean "everything": refused.
	_, err := agent(service.KeySpec{})
	is.True(err != nil)
	// Never an agent's: membership management.
	_, err = agent(service.KeySpec{Capabilities: []authz.Capability{authz.CapReadPrivate, authz.CapManageMember}})
	is.True(err != nil)
	// At most 90 days.
	_, err = agent(service.KeySpec{Preset: "analyst", ExpiresAt: time.Now().Add(100 * 24 * time.Hour)})
	is.True(err != nil)
	// Presets are for agent keys.
	_, err = authSvc.CreateKey(ctx, alice.String(), service.KeySpec{Name: "p", Preset: "analyst"})
	is.True(err != nil)

	// coverage: trigger_scan, held for approval, 30-day default expiry.
	plain, err := agent(service.KeySpec{Preset: "coverage"})
	is.NoErr(err)
	u, err := authSvc.ValidateAPIKey(ctx, plain)
	is.NoErr(err)
	is.True(u.KeyAllows(authz.CapTriggerScan))
	is.True(u.RequiresApproval(authz.CapTriggerScan))
	var expires time.Time
	is.NoErr(pool.QueryRow(ctx, `SELECT expires_at FROM api_key WHERE kind = 'agent'`).Scan(&expires))
	is.True(expires.After(time.Now().Add(29*24*time.Hour)) && expires.Before(time.Now().Add(31*24*time.Hour)))

	// An agent key cannot manage keys, its own included.
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		resp, err := doWithAuth(t, m, srv.URL+"/api/v1/auth/keys", `{"name":"x"}`, plain)
		is.NoErr(err)
		resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusForbidden)
	}

	// The key can describe itself, which is how ocidex-mcp decides its tools.
	var self struct {
		Kind             string   `json:"kind"`
		Capabilities     []string `json:"capabilities"`
		ApprovalRequired []string `json:"approvalRequired"`
		Namespaces       []string `json:"namespaces"`
		ExpiresAt        string   `json:"expiresAt"`
	}
	getJSON(t, srv.URL+"/api/v1/auth/keys/self", plain, &self)
	is.Equal(self.Kind, "agent")
	is.Equal(self.Capabilities, []string{"read_private", "trigger_scan"})
	is.Equal(self.ApprovalRequired, []string{"trigger_scan"})
	is.Equal(self.Namespaces, []string{ns})
	is.True(self.ExpiresAt != "")

	// The presets are listed.
	var presets struct {
		Presets []struct {
			Name string `json:"name"`
		} `json:"presets"`
		MaxExpiryDays int `json:"maxExpiryDays"`
	}
	getJSON(t, srv.URL+"/api/v1/auth/key-presets", plain, &presets)
	is.Equal(len(presets.Presets), 3)
	is.Equal(presets.MaxExpiryDays, 90)
}
