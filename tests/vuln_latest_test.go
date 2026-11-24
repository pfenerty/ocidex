package tests

import (
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// TestTopVulnsLatestTagsAndFixAge: the list counts artifacts whose latest tag
// still carries a CVE (not every SBOM ever ingested), sorts by how long a fix
// has been out for those, and gives a signed-in caller running pods.
//
//	still  1.0.0, 1.1.0, 1.2.0 all carry CVE-A (fixed 10 d ago)  -> latest affected
//	fixed  1.0.0 carries CVE-A, 1.1.0 does not                   -> not counted
//	newer  1.0.0 carries CVE-B (fixed 2 d ago)                   -> latest affected
//	CVE-C  only on an old tag of "fixed" with no fix              -> 0 latest
func TestTopVulnsLatestTagsAndFixAge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	ctx := t.Context()
	f := movesFixture{t: t, pool: pool, now: time.Now()}

	owner := seedUser(t, pool, 9701, "latest-owner", "member")
	ns := seedNamespace(t, pool, "latest-ns", owner, "public")
	clusterID := seedCluster(t, pool, ns, "prod")

	comp := func(sbomID, name string) {
		t.Helper()
		_, err := pool.Exec(ctx, `INSERT INTO component (sbom_id, type, name, version, purl) VALUES ($1::uuid, 'library', $2, '1', $3)`,
			sbomID, name, "pkg:generic/"+name+"@1")
		is.NoErr(err)
	}
	still := f.artifact("ghcr.io/example/still")
	var stillDigest string
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		id, d := f.sbom(ns, still, tag{version: v})
		comp(id, "liba")
		stillDigest = d
	}
	fixed := f.artifact("ghcr.io/example/fixed")
	oldID, _ := f.sbom(ns, fixed, tag{version: "1.0.0"})
	comp(oldID, "liba")
	comp(oldID, "libc")
	newID, _ := f.sbom(ns, fixed, tag{version: "1.1.0"})
	comp(newID, "clean")
	newer := f.artifact("ghcr.io/example/newer")
	nid, _ := f.sbom(ns, newer, tag{version: "1.0.0"})
	comp(nid, "libb")

	seedAdvisory(t, pool, "CVE-2031-4001", "CVE-2031-4001", "HIGH", 7.5, "pkg:generic/liba@1")
	seedAdvisory(t, pool, "CVE-2031-4002", "CVE-2031-4002", "HIGH", 7.5, "pkg:generic/libb@1")
	seedAdvisory(t, pool, "CVE-2031-4003", "CVE-2031-4003", "HIGH", 7.5, "pkg:generic/libc@1")
	for cve, days := range map[string]int{"CVE-2031-4001": 10, "CVE-2031-4002": 2} {
		_, err := pool.Exec(ctx, `UPDATE package_vulnerability SET fixed_version = '2', fix_state = 'fixed',
			fix_available_since = now() - make_interval(days => $2) WHERE vulnerability_id = $1`, cve, days)
		is.NoErr(err)
	}
	f.workload(clusterID, "apps", "still", stillDigest, 3)
	refreshRollups(t, pool)

	svc := service.NewSearchService(pool)
	page, err := svc.ListTopVulnerabilities(ctx, service.TopVulnFilter{
		Limit: 10, Sort: "fixAge", SortDir: "desc",
		Visibility: service.VisibilityFilter{UserID: owner.String()},
	})
	is.NoErr(err)
	type row struct {
		id            string
		sboms, latest int64
		pods          int64
		hasFix        bool
	}
	got := make([]row, 0, len(page.Data))
	for _, e := range page.Data {
		r := row{id: e.CanonicalID, sboms: e.AffectedSbomCount, latest: e.LatestAffectedCount, hasFix: e.FixAvailableSince != nil}
		if e.RunningPods != nil {
			r.pods = *e.RunningPods
		}
		got = append(got, r)
	}
	is.Equal(got, []row{
		{"CVE-2031-4001", 4, 1, 3, true},  // fix out 10 d, only "still" ships it
		{"CVE-2031-4002", 1, 1, 0, true},  // fix out 2 d
		{"CVE-2031-4003", 1, 0, 0, false}, // no latest tag carries it: last
	})

	// Signed out: no pods figure at all.
	anon, err := svc.ListTopVulnerabilities(ctx, service.TopVulnFilter{Limit: 10})
	is.NoErr(err)
	for _, e := range anon.Data {
		is.True(e.RunningPods == nil)
	}
}
