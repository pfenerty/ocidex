package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/matryer/is"
)

// TestDependencyGraphEndpoint covers GET /api/v1/sboms/{id}/dependencies, the
// payload PackagesTab's tree mode is built from.
//
// It reuses diffTreeFromSBOM, whose graph is exactly the shape that matters
// here: a metadata.component bom-ref anchoring three direct dependencies, one
// of which (openssl) pulls in a transitive one (libssl1.1).
func TestDependencyGraphEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	memberID := seedUser(t, pool, 9101, "dep-graph-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "dep-graph-test", nil)
	is.NoErr(err)

	resp, err := doWithAuth(t, http.MethodPost, srv.URL+ingestPath(t, pool, memberID), diffTreeFromSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingested map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingested))
	resp.Body.Close()
	sbomID := ingested["id"].(string)

	resp, err = doGet(t, fmt.Sprintf("%s/api/v1/sboms/%s/dependencies", srv.URL, sbomID))
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var graph struct {
		Nodes []struct {
			Name     string  `json:"name"`
			BomRef   *string `json:"bomRef"`
			IsDirect bool    `json:"isDirect"`
		} `json:"nodes"`
		Edges []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"edges"`
		Roots []string `json:"roots"`
	}
	is.NoErr(json.NewDecoder(resp.Body).Decode(&graph))
	resp.Body.Close()

	is.Equal(len(graph.Nodes), 4)
	is.Equal(len(graph.Edges), 4)

	// Roots are the metadata.component's children, not every node without an
	// in-edge: libssl1.1 hangs off openssl and must not appear.
	is.Equal(len(graph.Roots), 3)

	direct := map[string]bool{}
	for _, n := range graph.Nodes {
		direct[n.Name] = n.IsDirect
	}
	// The direct/transitive split. Before this was populated every node came
	// back isDirect:false, which reads as "this SBOM has no direct
	// dependencies" — a claim no SBOM with a dependency graph can make.
	is.True(direct["alpine-baselayout"])
	is.True(direct["busybox"])
	is.True(direct["openssl"])
	is.True(!direct["libssl1.1"])
}
