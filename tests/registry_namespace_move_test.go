package tests

import (
	"io"
	"net/http"
	"testing"

	"github.com/matryer/is"
)

// TestRegistryNamespaceMove covers ocidex-nps9.33: an update naming another
// namespace moves the registry, every SBOM it is the source of, and the
// artifact's visibility link, in one step. It is what lets a registry join the
// namespace a cluster resolves running images against.
func TestRegistryNamespaceMove(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	owner := seedUser(t, pool, 9301, "move-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), owner, "move", nil)
	is.NoErr(err)

	fromNS := seedNamespace(t, pool, "move-from", owner, "public")
	toNS := seedNamespace(t, pool, "move-to", owner, "public")
	regID := seedRegistryInNamespace(t, pool, fromNS, "move-reg")

	var artifactID string
	is.NoErr(pool.QueryRow(t.Context(),
		`INSERT INTO artifact (type, name) VALUES ('container', 'registry.move-reg.example.com/app') RETURNING id`,
	).Scan(&artifactID))
	_, err = pool.Exec(t.Context(), `
		INSERT INTO sbom (spec_version, raw_bom, artifact_id, namespace_id, source_id, subject_version)
		VALUES ('1.6', '{}'::jsonb, $1, $2, $3, 'v1'), ('1.6', '{}'::jsonb, $1, $2, $3, 'v2')`,
		artifactID, fromNS, regID)
	is.NoErr(err)
	_, err = pool.Exec(t.Context(),
		`INSERT INTO artifact_namespace (artifact_id, namespace_id) VALUES ($1, $2)`, artifactID, fromNS)
	is.NoErr(err)

	body := `{"name":"move-reg","type":"generic","url":"registry.move-reg.example.com","insecure":false,"enabled":true,"namespace":"move-to"}`
	resp, err := doWithAuth(t, http.MethodPatch, srv.URL+"/api/v1/registries/"+regID, body, ownerKey)
	is.NoErr(err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("move: status %d: %s", resp.StatusCode, msg)
	}

	var srcNS string
	is.NoErr(pool.QueryRow(t.Context(), `SELECT namespace_id::text FROM source WHERE id = $1`, regID).Scan(&srcNS))
	is.Equal(srcNS, toNS)

	var left int
	is.NoErr(pool.QueryRow(t.Context(),
		`SELECT count(*) FROM sbom WHERE source_id = $1 AND namespace_id <> $2`, regID, toNS).Scan(&left))
	is.Equal(left, 0) // every SBOM moved

	var links []string
	rows, err := pool.Query(t.Context(),
		`SELECT namespace_id::text FROM artifact_namespace WHERE artifact_id = $1`, artifactID)
	is.NoErr(err)
	for rows.Next() {
		var ns string
		is.NoErr(rows.Scan(&ns))
		links = append(links, ns)
	}
	is.NoErr(rows.Err())
	is.Equal(links, []string{toNS}) // linked in the new namespace, unlinked from the old
}
