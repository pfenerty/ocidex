package tests

import (
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// TestDiscoverCriticalCuts: the largest critical drop per public artifact,
// between consecutive stable versions of one line, both vuln-matched.
func TestDiscoverCriticalCuts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	f := movesFixture{t: t, pool: pool, now: time.Now()}

	pub := seedNamespace(t, pool, "cuts-public", seedUser(t, pool, 9601, "cuts-pub", "member"), "public")
	priv := seedNamespace(t, pool, "cuts-private", seedUser(t, pool, 9602, "cuts-priv", "member"), "private")

	dex := f.artifact("ghcr.io/dexidp/dex")
	f.sbom(pub, dex, tag{version: "v2.45.1", critical: 16})
	f.sbom(pub, dex, tag{version: "v2.46.0", critical: 3})
	f.sbom(pub, dex, tag{version: "v2.46.1", critical: 2})
	// A prerelease and the distroless line are not consecutive with these.
	f.sbom(pub, dex, tag{version: "v2.47.0-rc.1", critical: 0})
	f.sbom(pub, dex, tag{version: "v2.45.1-distroless", flavor: "debian", critical: 11})
	f.sbom(pub, dex, tag{version: "v2.46.0-distroless", flavor: "debian", critical: 9})

	// An unmatched release would read as clean: no cut.
	unmatched := f.artifact("ghcr.io/example/unmatched")
	f.sbom(pub, unmatched, tag{version: "1.0.0", critical: 5})
	f.sbom(pub, unmatched, tag{version: "1.1.0", unsettled: true})

	// Private content never shows.
	secret := f.artifact("ghcr.io/example/secret")
	f.sbom(priv, secret, tag{version: "1.0.0", critical: 50})
	f.sbom(priv, secret, tag{version: "1.1.0"})

	d, err := service.NewSearchService(pool).WarmDiscovery(t.Context())
	is.NoErr(err)
	is.Equal(len(d.CriticalCuts), 1)
	c := d.CriticalCuts[0]
	is.Equal(c.Name, "ghcr.io/dexidp/dex")
	is.Equal(c.FromVersion, "v2.45.1")
	is.Equal(c.ToVersion, "v2.46.0")
	is.Equal(c.FromCritical, int64(16))
	is.Equal(c.ToCritical, int64(3))
	is.True(c.ReleasedAt != nil)
}

// TestDiscoverTopPackages: one package per ecosystem, ranked by public SBOM
// count, skipping packages with no known critical or high.
func TestDiscoverTopPackages(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	f := movesFixture{t: t, pool: pool, now: time.Now()}

	pub := seedNamespace(t, pool, "pkgs-public", seedUser(t, pool, 9611, "pkgs-pub", "member"), "public")
	priv := seedNamespace(t, pool, "pkgs-private", seedUser(t, pool, 9612, "pkgs-priv", "member"), "private")

	comp := func(sbomID, name, version, purl string) {
		t.Helper()
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO component (sbom_id, type, name, version, purl) VALUES ($1::uuid, 'library', $2, $3, $4)`,
			sbomID, name, version, purl); err != nil {
			t.Fatal(err)
		}
	}
	for i, v := range []string{"go1.25.6", "go1.26.1", "go1.26.1"} {
		a := f.artifact("ghcr.io/example/go-app-" + string(rune('a'+i)))
		id, _ := f.sbom(pub, a, tag{version: "1.0.0"})
		comp(id, "stdlib", v, "pkg:golang/stdlib@"+v)
		comp(id, "golang.org/x/text", "v0.1.0", "pkg:golang/golang.org/x/text@v0.1.0") // more common, but clean
		if i < 2 {
			comp(id, "zlib", "1.3.1", "pkg:apk/wolfi/zlib@1.3.1")
		}
		comp(id, "base-files", "13", "pkg:deb/debian/base-files@13")
	}
	extra := f.artifact("ghcr.io/example/go-app-x")
	id, _ := f.sbom(pub, extra, tag{version: "1.0.0"})
	comp(id, "golang.org/x/text", "v0.1.0", "pkg:golang/golang.org/x/text@v0.1.0")
	// Private SBOMs do not count.
	for i := 0; i < 5; i++ {
		a := f.artifact("ghcr.io/example/private-" + string(rune('a'+i)))
		pid, _ := f.sbom(priv, a, tag{version: "1.0.0"})
		comp(pid, "openssl", "3.0.0", "pkg:apk/wolfi/openssl@3.0.0")
	}
	seedAdvisory(t, pool, "CVE-2031-2001", "CVE-2031-2001", "CRITICAL", 9.8, "pkg:golang/stdlib@go1.25.6")
	seedAdvisory(t, pool, "CVE-2031-2002", "CVE-2031-2002", "HIGH", 7.0, "pkg:apk/wolfi/zlib@1.3.1")
	seedAdvisory(t, pool, "CVE-2031-2003", "CVE-2031-2003", "CRITICAL", 9.8, "pkg:apk/wolfi/openssl@3.0.0")
	refreshRollups(t, pool)

	d, err := service.NewSearchService(pool).WarmDiscovery(t.Context())
	is.NoErr(err)
	type row struct {
		eco, name       string
		sboms, versions int64
		crit, high      int64
	}
	got := make([]row, 0, len(d.TopPackages))
	for _, p := range d.TopPackages {
		got = append(got, row{p.Ecosystem, p.Name, p.SbomCount, p.VersionCount, p.Critical, p.High})
	}
	is.Equal(got, []row{
		{"golang", "stdlib", 3, 2, 1, 0},
		{"apk", "zlib", 2, 1, 0, 1},
	})
}
