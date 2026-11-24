package tests

import (
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// TestArtifactListTellsCleanFromUnscanned: an artifact whose newest SBOM was
// matched and has no findings is listed as matched, so the list can say
// "0 known"; one never matched is not, so it says "not scanned".
func TestArtifactListTellsCleanFromUnscanned(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	f := movesFixture{t: t, pool: pool, now: time.Now()}

	owner := seedUser(t, pool, 9801, "list-matched-owner", "member")
	ns := seedNamespace(t, pool, "list-matched-ns", owner, "public")
	f.sbom(ns, f.artifact("example.test/clean"), tag{version: "1.0.0"})
	f.sbom(ns, f.artifact("example.test/unscanned"), tag{version: "1.0.0", unsettled: true})
	f.sbom(ns, f.artifact("example.test/vulnerable"), tag{version: "1.0.0", critical: 1})

	page, err := service.NewSearchService(pool).ListArtifacts(t.Context(), service.ArtifactFilter{
		Limit: 10, Visibility: service.VisibilityFilter{UserID: owner.String()},
	})
	is.NoErr(err)
	type row struct {
		matched, hasVulns bool
	}
	got := map[string]row{}
	for _, a := range page.Data {
		got[a.Name] = row{a.VulnMatched, a.Vulns != nil}
	}
	is.Equal(got, map[string]row{
		"example.test/clean":      {true, false},
		"example.test/unscanned":  {false, false},
		"example.test/vulnerable": {true, true},
	})
}
