package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/matryer/is"
)

// mustPostJSON posts body and fails with the server's error body on an
// unexpected status, so a rejected field name is visible rather than an
// unattributable status mismatch.
func mustPostJSON(t *testing.T, url, body, apiKey string, want int) map[string]any {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodPost, url, body, apiKey)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s: status %d (want %d): %s", url, resp.StatusCode, want, b)
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("POST %s: decode: %v", url, err)
	}
	return out
}

// inventoryBody builds a snapshot body from (k8s namespace, workload, container,
// image ref, digest) tuples.
func inventoryBody(t *testing.T, workloads ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"workloads": workloads})
	if err != nil {
		t.Fatalf("marshalling inventory: %v", err)
	}
	return string(b)
}

func wl(ns, name, container, ref, dgst string, pods int) map[string]any {
	w := map[string]any{
		"k8s_namespace":  ns,
		"workload_kind":  "Deployment",
		"workload_name":  name,
		"container_name": container,
		"image_ref":      ref,
		"pod_count":      pods,
	}
	if dgst != "" {
		w["image_digest"] = dgst
	}
	return w
}

// TestClusterInventoryAPI exercises the two properties ADR-044 makes load-bearing
// at the HTTP boundary: only the owner of the cluster's namespace may push a
// snapshot (K8), and a snapshot is a full replacement rather than a merge (K7).
//
// The prune assertion goes through HTTP rather than the service layer on purpose
// — the repository-level test already proves the SQL, and what is untested
// without this is whether the handler passes the whole body through as one
// snapshot. A handler that merged instead of replaced would pass every
// service-level test.
func TestClusterInventoryAPI(t *testing.T) {
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

	ownerID := seedUser(t, pool, 2001, "cluster-owner", "member")
	otherID := seedUser(t, pool, 2002, "cluster-other", "member")

	ownerKey, err := authSvc.CreateAPIKey(ctx, ownerID, "test", "read-write")
	is.NoErr(err)
	otherKey, err := authSvc.CreateAPIKey(ctx, otherID, "test", "read-write")
	is.NoErr(err)
	// A read-scoped key belonging to the owner: it must still be refused, since
	// the inventory push is a write however much it reads like a report.
	ownerReadKey, err := authSvc.CreateAPIKey(ctx, ownerID, "test-ro", "read")
	is.NoErr(err)

	// Public namespace on purpose: it makes the cluster readable by anyone, which
	// is exactly the case where confusing visibility for ownership would open the
	// inventory to writes from anyone.
	ns := mustPostJSON(t, srv.URL+"/api/v1/namespaces",
		`{"name":"cluster-ns","visibility":"public"}`, ownerKey, http.StatusCreated)
	nsID := ns["id"].(string)

	cluster := mustPostJSON(t, srv.URL+"/api/v1/clusters",
		`{"namespace_id":"`+nsID+`","name":"prod","description":"east"}`, ownerKey, http.StatusCreated)
	clusterID := cluster["id"].(string)
	is.Equal(cluster["last_seen_at"], nil) // never reported
	inventoryURL := srv.URL + "/api/v1/clusters/" + clusterID + "/inventory"
	workloadsURL := srv.URL + "/api/v1/clusters/" + clusterID + "/workloads"

	const (
		digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	// The two workloads live in different Kubernetes namespaces, so the prune
	// below also proves identity is scoped by k8s_namespace rather than by
	// workload name alone.
	first := inventoryBody(t,
		wl("default", "api", "api", "ghcr.io/x/api:1", digestA, 3),
		wl("frontend", "web", "web", "ghcr.io/x/web:1", digestB, 1),
	)

	t.Run("non-owner is rejected", func(t *testing.T) {
		is := is.New(t)
		resp, err := doWithAuth(t, http.MethodPost, inventoryURL, first, otherKey)
		is.NoErr(err)
		defer resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusForbidden)
	})

	t.Run("anonymous is rejected", func(t *testing.T) {
		is := is.New(t)
		resp, err := doWithAuth(t, http.MethodPost, inventoryURL, first, "")
		is.NoErr(err)
		defer resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusUnauthorized)
	})

	t.Run("owner's read-scoped key is rejected", func(t *testing.T) {
		is := is.New(t)
		resp, err := doWithAuth(t, http.MethodPost, inventoryURL, first, ownerReadKey)
		is.NoErr(err)
		defer resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusForbidden)
	})

	t.Run("no rejected push left a workload behind", func(t *testing.T) {
		is := is.New(t)
		var n int
		is.NoErr(pool.QueryRow(ctx,
			"SELECT count(*) FROM cluster_workload WHERE cluster_id = $1", clusterID).Scan(&n))
		is.Equal(n, 0)
	})

	t.Run("owner push is accepted", func(t *testing.T) {
		is := is.New(t)
		out := mustPostJSON(t, inventoryURL, first, ownerKey, http.StatusOK)
		is.Equal(out["accepted"], float64(2))
		is.Equal(out["pruned"], float64(0))
		is.True(out["seen_at"] != "")
	})

	t.Run("second snapshot prunes what it omits", func(t *testing.T) {
		is := is.New(t)
		// "web" disappears, "api" scales down, "worker" appears with no resolvable
		// digest.
		second := inventoryBody(t,
			wl("default", "api", "api", "ghcr.io/x/api:1", digestA, 1),
			wl("batch", "worker", "worker", "ghcr.io/x/worker:1", "", 2),
		)
		out := mustPostJSON(t, inventoryURL, second, ownerKey, http.StatusOK)
		is.Equal(out["accepted"], float64(2))
		is.Equal(out["pruned"], float64(1)) // web

		resp, err := doWithAuth(t, http.MethodGet, workloadsURL, "", ownerKey)
		is.NoErr(err)
		defer resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusOK)

		var body struct {
			Data []struct {
				WorkloadName string `json:"workload_name"`
				ImageDigest  string `json:"image_digest"`
				PodCount     int    `json:"pod_count"`
				MatchState   string `json:"match_state"`
			} `json:"data"`
			Coverage struct {
				Total        int `json:"total"`
				Matched      int `json:"matched"`
				Unknown      int `json:"unknown"`
				Unresolvable int `json:"unresolvable"`
			} `json:"coverage"`
		}
		is.NoErr(json.NewDecoder(resp.Body).Decode(&body))
		is.Equal(len(body.Data), 2)

		byName := map[string]int{}
		for i, w := range body.Data {
			byName[w.WorkloadName] = i
		}
		_, hasWeb := byName["web"]
		is.True(!hasWeb) // pruned

		api := body.Data[byName["api"]]
		is.Equal(api.PodCount, 1)           // updated in place, not duplicated
		is.Equal(api.MatchState, "unknown") // real digest, no SBOM ingested

		worker := body.Data[byName["worker"]]
		is.Equal(worker.ImageDigest, "")
		is.Equal(worker.MatchState, "unresolvable")

		// Coverage must account for every row, so a caller cannot report zero
		// findings without also seeing that nothing was matched (K5).
		is.Equal(body.Coverage.Total, 2)
		is.Equal(body.Coverage.Matched, 0)
		is.Equal(body.Coverage.Unknown, 1)
		is.Equal(body.Coverage.Unresolvable, 1)
	})

	t.Run("empty snapshot means running nothing, not no report", func(t *testing.T) {
		is := is.New(t)
		out := mustPostJSON(t, inventoryURL, `{"workloads":[]}`, ownerKey, http.StatusOK)
		is.Equal(out["accepted"], float64(0))
		is.Equal(out["pruned"], float64(2))

		resp, err := doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/clusters/"+clusterID, "", ownerKey)
		is.NoErr(err)
		defer resp.Body.Close()
		var got map[string]any
		is.NoErr(json.NewDecoder(resp.Body).Decode(&got))
		// last_seen_at is what separates a cluster running nothing from a cluster
		// whose agent has died (K2), so an empty snapshot must still stamp it.
		is.True(got["last_seen_at"] != nil && got["last_seen_at"] != "")
	})

	t.Run("non-owner may still read a public cluster", func(t *testing.T) {
		is := is.New(t)
		resp, err := doWithAuth(t, http.MethodGet, workloadsURL, "", otherKey)
		is.NoErr(err)
		defer resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusOK)
	})

	t.Run("mutations require ownership too", func(t *testing.T) {
		is := is.New(t)
		resp, err := doWithAuth(t, http.MethodPatch, srv.URL+"/api/v1/clusters/"+clusterID,
			`{"name":"hijacked"}`, otherKey)
		is.NoErr(err)
		resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusForbidden)

		resp, err = doWithAuth(t, http.MethodDelete, srv.URL+"/api/v1/clusters/"+clusterID, "", otherKey)
		is.NoErr(err)
		resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusForbidden)
	})
}
