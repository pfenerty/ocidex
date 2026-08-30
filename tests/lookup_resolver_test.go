package tests

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/matryer/is"
)

// TestLookupSBOM_WithoutEnrichment exercises the ADR-042 SBOM resolver against an
// SBOM that carries no enrichment rows at all — the state every uploaded SBOM is
// in until a worker reaches it, and the state it stays in when no enricher runs.
//
// That is the case the resolver used to fail on: its architecture column is
// COALESCEd out of the oci-metadata and user enrichments, and with neither
// present the value is NULL, which the generated NOT NULL scan target rejected —
// a 500 on a lookup of a perfectly ordinary SBOM (ocidex-klj4). It reproduces
// only with a real database, which is why it lives here and not beside the
// handler.
func TestLookupSBOM_WithoutEnrichment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	i := is.New(t)
	ctx := t.Context()

	userID := seedUser(t, pool, 7401, "lookup-member", "member")
	key, err := authSvc.CreateAPIKey(ctx, userID, "lookup-test", nil)
	i.NoErr(err)

	resp, err := doWithAuth(t, http.MethodPost, srv.URL+ingestPath(t, pool, userID), minimalSBOM, key)
	i.NoErr(err)
	defer resp.Body.Close()
	i.Equal(resp.StatusCode, http.StatusCreated)

	var ingested struct {
		ID string `json:"id"`
	}
	i.NoErr(json.NewDecoder(resp.Body).Decode(&ingested))

	var artifactName string
	i.NoErr(pool.QueryRow(ctx,
		`SELECT a.name FROM artifact a JOIN sbom s ON s.artifact_id = a.id WHERE s.id = $1`,
		ingested.ID).Scan(&artifactName))

	q := url.Values{"artifact": {artifactName}, "version": {"24.04"}}
	found, err := doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/sboms/lookup?"+q.Encode(), "", key)
	i.NoErr(err)
	defer found.Body.Close()
	i.Equal(found.StatusCode, http.StatusOK)

	var body struct {
		ID string `json:"id"`
	}
	i.NoErr(json.NewDecoder(found.Body).Decode(&body))
	i.Equal(body.ID, ingested.ID)
}
