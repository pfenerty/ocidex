package tests

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// movesFixture seeds SBOMs for the upgrade-queue tests.
type movesFixture struct {
	t    *testing.T
	pool *pgxpool.Pool
	now  time.Time
}

// tag is one SBOM of an artifact: its tag, flavor, rollup counts, build age
// in days, and whether it has been vuln-matched long enough to be settled.
type tag struct {
	version, flavor string
	critical, high  int
	builtDaysAgo    int
	unsettled       bool
}

func (f movesFixture) artifact(name string) pgtype.UUID {
	f.t.Helper()
	var id pgtype.UUID
	if err := f.pool.QueryRow(f.t.Context(),
		`INSERT INTO artifact (type, name) VALUES ('container', $1) RETURNING id`, name).Scan(&id); err != nil {
		f.t.Fatalf("seed artifact %s: %v", name, err)
	}
	return id
}

// sbom inserts one tag, returning its id and digest.
func (f movesFixture) sbom(nsID string, artifactID pgtype.UUID, tg tag) (id, digest string) {
	f.t.Helper()
	ctx := f.t.Context()
	digest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(artifactID.String()+tg.version+tg.flavor)))
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO sbom (spec_version, raw_bom, digest, artifact_id, namespace_id, subject_version, flavor)
		VALUES ('1.6', '{}'::jsonb, $1, $2, $3::uuid, $4, NULLIF($5, '')) RETURNING id::text
	`, digest, artifactID, nsID, tg.version, tg.flavor).Scan(&id); err != nil {
		f.t.Fatalf("seed sbom %s: %v", tg.version, err)
	}
	built := f.now.Add(-time.Duration(tg.builtDaysAgo)*24*time.Hour - time.Hour).UTC().Format(time.RFC3339)
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO enrichment (sbom_id, enricher_name, status, data)
		VALUES ($1::uuid, 'oci-metadata', 'success', jsonb_build_object('created', $2::text))
	`, id, built); err != nil {
		f.t.Fatalf("seed enrichment: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO sbom_vuln_rollup (sbom_id, namespace_id, critical, high) VALUES ($1::uuid, $2::uuid, $3, $4)
	`, id, nsID, tg.critical, tg.high); err != nil {
		f.t.Fatalf("seed rollup: %v", err)
	}
	if !tg.unsettled {
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO sbom_vuln_match (sbom_id, db_built_at, matched_at) VALUES ($1::uuid, now(), now() - interval '1 hour')
		`, id); err != nil {
			f.t.Fatalf("seed match: %v", err)
		}
	}
	return id, digest
}

// critical attaches a critical finding to a component of an SBOM.
func (f movesFixture) critical(sbomID, pkg, version, cve string, cvss float32, fixedVersion, fixState string) {
	f.t.Helper()
	ctx := f.t.Context()
	purl := "pkg:generic/" + pkg + "@" + version
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO component (sbom_id, type, name, version, purl) VALUES ($1::uuid, 'library', $2, $3, $4)
	`, sbomID, pkg, version, purl); err != nil {
		f.t.Fatalf("seed component: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO vulnerability (id, aliases, canonical_id, severity, cvss_score, summary)
		VALUES ($1, ARRAY[$1]::text[], $1, 'CRITICAL', $2, 'seeded') ON CONFLICT (id) DO NOTHING
	`, cve, cvss); err != nil {
		f.t.Fatalf("seed vulnerability: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO package_vulnerability (purl, vulnerability_id, fixed_version, fix_state)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, '')) ON CONFLICT DO NOTHING
	`, purl, cve, fixedVersion, fixState); err != nil {
		f.t.Fatalf("seed package vulnerability: %v", err)
	}
}

func (f movesFixture) workload(clusterID, k8sNS, name, digest string, pods int) {
	f.t.Helper()
	if _, err := f.pool.Exec(f.t.Context(), `
		INSERT INTO cluster_workload (cluster_id, k8s_namespace, workload_kind, workload_name, container_name, image_ref, image_digest, pod_count)
		VALUES ($1::uuid, $2, 'Deployment', $3, 'main', $3, $4, $5)
	`, clusterID, k8sNS, name, digest, pods); err != nil {
		f.t.Fatalf("seed workload %s: %v", name, err)
	}
}

func getMoves(t *testing.T, baseURL, key string) service.Moves {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/users/me/moves", "", key)
	if err != nil {
		t.Fatalf("get moves: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get moves: status %d", resp.StatusCode)
	}
	var m service.Moves
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode moves: %v", err)
	}
	return m
}

// TestMyMovesFleet checks the upgrade queue against a fleet computed by hand.
//
//	dex   (auth, 2 pods)  v2.45.1 alpine 16/89 -> v2.46.1 2/36; first better
//	      v2.46.0 built 47 d ago; v2.46.1-distroless 1/21 is the alternative;
//	      v2.47.0-rc.1 (prerelease) and v2.47.0 (unsettled) are not candidates.
//	flux  (auth 1, flux-system 1) v1.9.6 11/64 -> v1.10.2 1/13; first v1.10.0, 30 d.
//	pg    (databases, 1)  18.6 1/47 -> 18.7 1/45, 11 d.
//	clean (flux-system 1) 1.0.0 0/0; 1.1.0 is 0/1, worse, so no upgrade.
//	an unmatched digest is left out.
func TestMyMovesFleet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	f := movesFixture{t: t, pool: pool, now: time.Now()}

	owner := seedUser(t, pool, 9501, "moves-owner", "member")
	nsID := seedNamespace(t, pool, "moves-fleet", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "homelab")

	dex := f.artifact("ghcr.io/dexidp/dex")
	dexRun, dexDigest := f.sbom(nsID, dex, tag{version: "v2.45.1", flavor: "alpine", critical: 16, high: 89, builtDaysAgo: 90})
	f.sbom(nsID, dex, tag{version: "v2.45.1-distroless", flavor: "debian", critical: 11, high: 53, builtDaysAgo: 90})
	f.sbom(nsID, dex, tag{version: "v2.46.0", flavor: "alpine", critical: 3, high: 40, builtDaysAgo: 47})
	f.sbom(nsID, dex, tag{version: "v2.46.0-distroless", flavor: "debian", critical: 2, high: 25, builtDaysAgo: 47})
	dexTarget, _ := f.sbom(nsID, dex, tag{version: "v2.46.1", flavor: "alpine", critical: 2, high: 36, builtDaysAgo: 20})
	f.sbom(nsID, dex, tag{version: "v2.46.1-distroless", flavor: "debian", critical: 1, high: 21, builtDaysAgo: 20})
	f.sbom(nsID, dex, tag{version: "v2.47.0-rc.1", flavor: "alpine", builtDaysAgo: 5})
	f.sbom(nsID, dex, tag{version: "v2.47.0", flavor: "alpine", builtDaysAgo: 1, unsettled: true})

	flux := f.artifact("ghcr.io/fluxcd/kustomize-controller")
	_, fluxDigest := f.sbom(nsID, flux, tag{version: "v1.9.6", critical: 11, high: 64, builtDaysAgo: 60})
	f.sbom(nsID, flux, tag{version: "v1.10.0", critical: 5, high: 20, builtDaysAgo: 30})
	fluxTarget, _ := f.sbom(nsID, flux, tag{version: "v1.10.2", critical: 1, high: 13, builtDaysAgo: 10})

	pg := f.artifact("ghcr.io/cloudnative-pg/postgresql")
	_, pgDigest := f.sbom(nsID, pg, tag{version: "18.6", critical: 1, high: 47, builtDaysAgo: 40})
	pgTarget, _ := f.sbom(nsID, pg, tag{version: "18.7", critical: 1, high: 45, builtDaysAgo: 11})

	clean := f.artifact("ghcr.io/example/clean")
	_, cleanDigest := f.sbom(nsID, clean, tag{version: "1.0.0", builtDaysAgo: 30})
	f.sbom(nsID, clean, tag{version: "1.1.0", high: 1, builtDaysAgo: 3})

	f.workload(clusterID, "auth", "dex", dexDigest, 2)
	f.workload(clusterID, "auth", "flux-shadow", fluxDigest, 1)
	f.workload(clusterID, "flux-system", "kustomize-controller", fluxDigest, 1)
	f.workload(clusterID, "databases", "pg", pgDigest, 1)
	f.workload(clusterID, "flux-system", "clean", cleanDigest, 1)
	f.workload(clusterID, "auth", "mystery", "sha256:"+fmt.Sprintf("%064d", 7), 3)

	// Left after upgrading: zlib in dex's and flux's targets, libxml2 in pg's
	// (won't fix). A critical only the running dex has is closed by the
	// upgrade and must not appear.
	f.critical(dexTarget, "zlib", "1.3.2", "CVE-2031-1001", 9.4, "1.4", "fixed")
	f.critical(fluxTarget, "zlib", "1.3.2", "CVE-2031-1001", 9.4, "1.4", "fixed")
	f.critical(pgTarget, "libxml2", "2.9.14", "CVE-2031-1002", 9.8, "", "wont-fix")
	f.critical(dexRun, "openssl", "3.5.5", "CVE-2031-1003", 9.1, "3.5.8", "fixed")

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()
	key, err := authSvc.CreateAPIKey(t.Context(), owner.String(), "moves", nil)
	is.NoErr(err)
	m := getMoves(t, srv.URL, key)

	is.Equal(m.Source, "cluster")
	type row struct {
		image, running, target, first string
		waiting                       int
		pods                          int64
		namespaces                    string
		before, after                 service.CritHigh
		alt                           string
	}
	got := make([]row, 0, len(m.Upgrades))
	for _, u := range m.Upgrades {
		r := row{image: u.Image, running: u.Running.Tag, target: u.Target.Tag, first: u.FirstBetter.Tag,
			waiting: u.WaitingDays, pods: u.Pods, namespaces: fmt.Sprint(u.Namespaces), before: u.Before, after: u.After}
		if u.Alternative != nil {
			r.alt = fmt.Sprintf("%s %d/%d", u.Alternative.Tag, u.Alternative.After.Critical, u.Alternative.After.High)
		}
		got = append(got, r)
	}
	is.Equal(got, []row{
		{"ghcr.io/dexidp/dex", "v2.45.1", "v2.46.1", "v2.46.0", 47, 2, "[auth]", service.CritHigh{Critical: 16, High: 89}, service.CritHigh{Critical: 2, High: 36}, "v2.46.1-distroless 1/21"},
		{"ghcr.io/fluxcd/kustomize-controller", "v1.9.6", "v1.10.2", "v1.10.0", 30, 2, "[auth flux-system]", service.CritHigh{Critical: 11, High: 64}, service.CritHigh{Critical: 1, High: 13}, ""},
		{"ghcr.io/cloudnative-pg/postgresql", "18.6", "18.7", "18.7", 11, 1, "[databases]", service.CritHigh{Critical: 1, High: 47}, service.CritHigh{Critical: 1, High: 45}, ""},
	})

	is.Equal(m.Totals, service.MovesTotals{
		Images: 4, Pods: 6,
		Before:   service.CritHigh{Critical: 28, High: 200},
		After:    service.CritHigh{Critical: 4, High: 94},
		Upgrades: 3, UpgradesCutCrit: 2,
		LongestWaitDays: 47, LongestWaitImage: "ghcr.io/dexidp/dex",
		LeftoverCriticals: 2,
	})

	is.Equal(m.Namespaces, []service.NamespaceMoves{
		{Name: "auth", Images: 2, Pods: 3, Before: service.CritHigh{Critical: 27, High: 153}, After: service.CritHigh{Critical: 3, High: 49}},
		{Name: "flux-system", Images: 2, Pods: 2, Before: service.CritHigh{Critical: 11, High: 64}, After: service.CritHigh{Critical: 1, High: 13}},
		{Name: "databases", Images: 1, Pods: 1, Before: service.CritHigh{Critical: 1, High: 47}, After: service.CritHigh{Critical: 1, High: 45}},
	})

	is.Equal(len(m.LeftoverCriticals), 2)
	l0, l1 := m.LeftoverCriticals[0], m.LeftoverCriticals[1]
	is.Equal(l0.ID, "CVE-2031-1002")
	is.Equal(l0.Package, "libxml2")
	is.Equal(l0.FixState, "wont-fix")
	is.Equal(l0.FixedVersion, "")
	is.Equal(l0.Images, []string{"ghcr.io/cloudnative-pg/postgresql"})
	is.Equal(l1.ID, "CVE-2031-1001")
	is.Equal(*l1.CvssScore, float32(9.4))
	is.Equal(l1.PackageVersion, "1.3.2")
	is.Equal(l1.FixedVersion, "1.4")
	is.Equal(l1.Images, []string{"ghcr.io/dexidp/dex", "ghcr.io/fluxcd/kustomize-controller"})
}

// TestMyMovesWithoutCluster falls back to each owned artifact's newest owned
// tag, with newer public tags as the upgrades.
func TestMyMovesWithoutCluster(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	f := movesFixture{t: t, pool: pool, now: time.Now()}

	owner := seedUser(t, pool, 9502, "moves-nocluster", "member")
	mine := seedNamespace(t, pool, "moves-mine", owner, "private")
	upstreamOwner := seedUser(t, pool, 9503, "moves-upstream", "member")
	upstream := seedNamespace(t, pool, "moves-upstream", upstreamOwner, "public")

	app := f.artifact("ghcr.io/example/app")
	f.sbom(mine, app, tag{version: "1.0.0", critical: 2, high: 3, builtDaysAgo: 30})
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO artifact_namespace (artifact_id, namespace_id) VALUES ($1, $2::uuid) ON CONFLICT DO NOTHING`, app, mine); err != nil {
		t.Fatal(err)
	}
	f.sbom(upstream, app, tag{version: "1.1.0", builtDaysAgo: 5})

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()
	key, err := authSvc.CreateAPIKey(t.Context(), owner.String(), "moves", nil)
	is.NoErr(err)
	m := getMoves(t, srv.URL, key)

	is.Equal(m.Source, "owned")
	is.Equal(len(m.Upgrades), 1)
	u := m.Upgrades[0]
	is.Equal(u.Running.Tag, "1.0.0")
	is.Equal(u.Target.Tag, "1.1.0")
	is.Equal(u.WaitingDays, 5)
	is.Equal(u.Pods, int64(0))
	is.Equal(u.Namespaces, []string{"moves-mine"})
	is.Equal(u.After, service.CritHigh{})
}
