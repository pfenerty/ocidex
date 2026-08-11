package tests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// statsArtifactTypes reads the type breakdown and the total off GET /api/v1/stats.
func statsArtifactTypes(t *testing.T, baseURL, apiKey string) (map[string]int64, int64) {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/stats", "", apiKey)
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get stats: status %d", resp.StatusCode)
	}
	var body struct {
		ArtifactCount int64 `json:"artifact_count"`
		ArtifactTypes []struct {
			Type          string `json:"type"`
			ArtifactCount int64  `json:"artifact_count"`
		} `json:"artifact_types"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	byType := make(map[string]int64, len(body.ArtifactTypes))
	for _, e := range body.ArtifactTypes {
		byType[e.Type] = e.ArtifactCount
	}
	return byType, body.ArtifactCount
}

// The Home breakdown renders beside artifact_count, so the two have to describe
// the same artifact set: same visibility rule, and the chips summing to the
// total. The only way to prove that is against a real database — artifact_visible
// is a SQL function and the breakdown is a GROUP BY over it.
func TestDashboardStatsArtifactTypeBreakdown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc, searchSvc := setupServerWithStats(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7401, "stats-types-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "stats-types", "read-write")
	is.NoErr(err)

	// Two containers in a public namespace, one application in a private one.
	publicNS := seedNamespace(t, pool, "stats-types-public", ownerID, "public")
	publicSrc := seedSource(t, pool, publicNS, "oci_registry", "ghcr")
	ingestOK(t, srv.URL, ownerKey, "/api/v1/sboms?source="+publicSrc, minimalSBOM)
	ingestOK(t, srv.URL, ownerKey, "/api/v1/sboms?source="+publicSrc, alpineSBOM)

	privateNS := seedNamespace(t, pool, "stats-types-private", ownerID, "private")
	privateSrc := seedSource(t, pool, privateNS, "upload", "ci")
	ingestOK(t, srv.URL, ownerKey, uploadPath(privateSrc, "application", "ocidex",
		"sha256:7401740174017401740174017401740174017401740174017401740174017401"),
		relBinarySBOM)

	warmStats(t, searchSvc)

	// Anonymous: the private application must not appear, and the chips must
	// still add up to the total rendered next to them.
	byType, total := statsArtifactTypes(t, srv.URL, "")
	is.Equal(byType["container"], int64(2))
	is.Equal(byType["application"], int64(0)) // private, invisible
	var sum int64
	for _, n := range byType {
		sum += n
	}
	is.Equal(sum, total)

	// The other direction: a viewer who can see the private namespace gets the
	// application counted, so the assertion above is about visibility rather
	// than about the type never being reported at all.
	adminStats, err := searchSvc.WarmDashboardStats(t.Context(), service.VisibilityFilter{IsAdmin: true})
	is.NoErr(err)
	adminByType := make(map[string]int64, len(adminStats.ArtifactTypes))
	var adminSum int64
	for _, e := range adminStats.ArtifactTypes {
		adminByType[e.Type] = e.ArtifactCount
		adminSum += e.ArtifactCount
	}
	is.Equal(adminByType["container"], int64(2))
	is.Equal(adminByType["application"], int64(1))
	is.Equal(adminSum, adminStats.ArtifactCount)
}
