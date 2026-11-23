package tests

import (
	"net/http"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// TestAgentKeyQuotas pins ADR-0058 A6: an agent key's writes are counted per
// hour and refused with 429 and Retry-After once spent; scan requests have a
// budget of their own, counted when asked for even if held; and an agent's
// unknown-image ingest must name a bounded list of images.
func TestAgentKeyQuotas(t *testing.T) {
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

	alice := seedUser(t, pool, 9951, "quota-alice", "member")
	nsID := seedNamespace(t, pool, "quota-ns", alice, "public")
	regID := seedRegistryInNamespace(t, pool, nsID, "quota-reg")
	clusterID := seedCluster(t, pool, nsID, "quota-cluster")
	two, one := 2, 1
	agent, err := authSvc.CreateKey(ctx, alice.String(), service.KeySpec{
		Name: "agent", Kind: service.KeyKindAgent, Preset: "coverage", Namespaces: []string{nsID},
		WritesPerHour: &two, ScansPerHour: &one,
	})
	is.NoErr(err)

	// post returns the status and headers; the body is closed here.
	post := func(path, body string) (int, http.Header) {
		t.Helper()
		resp, err := doWithAuth(t, http.MethodPost, srv.URL+path, body, agent)
		is.NoErr(err)
		defer resp.Body.Close()
		return resp.StatusCode, resp.Header
	}

	// An unbounded ingest is refused before it can be held or counted as a scan.
	code, _ := post("/api/v1/clusters/"+clusterID+"/ingest-unknown", `{}`)
	is.Equal(code, http.StatusUnprocessableEntity)

	// First scan request: held (counts one write and the one scan).
	code, _ = post("/api/v1/registries/"+regID+"/scan", "")
	is.Equal(code, http.StatusAccepted)
	// Second: over the scan budget.
	code, hdr := post("/api/v1/registries/"+regID+"/scan", "")
	is.Equal(code, http.StatusTooManyRequests)
	is.True(hdr.Get("Retry-After") != "")

	// Refused requests gave their counts back, so one write is spent: the
	// held scan. Watching an artifact is the second; the third write is over.
	personal, err := authSvc.CreateAPIKey(ctx, alice.String(), "personal", nil)
	is.NoErr(err)
	r, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms?source="+seedSource(t, pool, nsID, "upload", "ci"), minimalSBOM, personal)
	is.NoErr(err)
	r.Body.Close()
	var artifactID string
	is.NoErr(pool.QueryRow(ctx, `SELECT id::text FROM artifact LIMIT 1`).Scan(&artifactID))
	watch := func(method string) int {
		t.Helper()
		r, err := doWithAuth(t, method, srv.URL+"/api/v1/users/me/watches/"+artifactID, "", agent)
		is.NoErr(err)
		r.Body.Close()
		return r.StatusCode
	}
	is.True(watch(http.MethodPut) < 300)
	is.Equal(watch(http.MethodDelete), http.StatusTooManyRequests)

	// The key reports its budgets.
	var self struct {
		ScansPerHour  int `json:"scansPerHour"`
		WritesPerHour int `json:"writesPerHour"`
	}
	getJSON(t, srv.URL+"/api/v1/auth/keys/self", agent, &self)
	is.Equal(self.ScansPerHour, 1)
	is.Equal(self.WritesPerHour, 2)

	// A budget over the installation maximum is refused.
	big := service.MaxAgentScansPerHour + 1
	_, err = authSvc.CreateKey(ctx, alice.String(), service.KeySpec{
		Name: "big", Kind: service.KeyKindAgent, Preset: "coverage", Namespaces: []string{nsID}, ScansPerHour: &big,
	})
	is.True(err != nil)
}
