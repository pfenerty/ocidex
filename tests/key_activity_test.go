package tests

import (
	"net/http"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// TestAgentKeyActivityIsRecorded pins ADR-0058 A5: an agent key's writes and
// refusals are recorded with the MCP tool it named, its reads are not, and only
// the key's holder can list them.
func TestAgentKeyActivityIsRecorded(t *testing.T) {
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

	alice := seedUser(t, pool, 9901, "activity-alice", "member")
	nsID := seedNamespace(t, pool, "activity-ns", alice, "public")
	personal, err := authSvc.CreateAPIKey(ctx, alice.String(), "personal", nil)
	is.NoErr(err)
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms?source="+seedSource(t, pool, nsID, "upload", "ci"), minimalSBOM, personal)
	is.NoErr(err)
	resp.Body.Close()
	var artifactID string
	is.NoErr(pool.QueryRow(ctx, `SELECT id::text FROM artifact LIMIT 1`).Scan(&artifactID))

	agent, err := authSvc.CreateKey(ctx, alice.String(), service.KeySpec{
		Name: "agent", Kind: service.KeyKindAgent, Namespaces: []string{nsID}, AgentLabel: "laptop",
	})
	is.NoErr(err)

	call := func(method, path, tool string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, srv.URL+path, nil)
		is.NoErr(err)
		req.Header.Set("Authorization", "Bearer "+agent)
		req.Header.Set("X-OCIDex-Agent-Tool", tool)
		resp, err := http.DefaultClient.Do(req)
		is.NoErr(err)
		resp.Body.Close()
		return resp.StatusCode
	}
	is.Equal(call(http.MethodGet, "/api/v1/artifacts?sufficient=false", "ocidex_search_artifacts"), http.StatusOK) // read: not recorded
	call(http.MethodPut, "/api/v1/users/me/watches/"+artifactID, "ocidex_watch_artifact")                          // write
	is.Equal(call(http.MethodGet, "/api/v1/users", "Not A Tool!"), http.StatusForbidden)                           // refusal; bad tool name dropped

	var keyID string
	is.NoErr(pool.QueryRow(ctx, `SELECT id::text FROM api_key WHERE kind = 'agent'`).Scan(&keyID))
	var out struct {
		Data []struct {
			Tool       string `json:"tool"`
			Method     string `json:"method"`
			Route      string `json:"route"`
			Status     int    `json:"status"`
			AgentLabel string `json:"agentLabel"`
		} `json:"data"`
	}
	getJSON(t, srv.URL+"/api/v1/auth/keys/"+keyID+"/activity", personal, &out)
	is.Equal(len(out.Data), 2)
	is.Equal(out.Data[0].Status, http.StatusForbidden)
	is.Equal(out.Data[0].Tool, "")
	is.Equal(out.Data[1].Method, http.MethodPut)
	is.Equal(out.Data[1].Tool, "ocidex_watch_artifact")
	is.Equal(out.Data[1].Route, "/api/v1/users/me/watches/{artifactId}")
	is.Equal(out.Data[1].AgentLabel, "laptop")

	// Someone else's key is not found.
	bob := seedUser(t, pool, 9902, "activity-bob", "member")
	bobKey, err := authSvc.CreateAPIKey(ctx, bob.String(), "bob", nil)
	is.NoErr(err)
	resp, err = doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/auth/keys/"+keyID+"/activity", "", bobKey)
	is.NoErr(err)
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusNotFound)
}
