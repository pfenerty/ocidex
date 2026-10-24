package tests

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/service"
)

// retentionSeed describes one SBOM for the ADR-0056 tests.
type retentionSeed struct {
	ns, source, artifact, version, digest, index string
	age                                          time.Duration
}

// seedRetentionArtifact inserts an artifact and returns its id.
func seedRetentionArtifact(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO artifact (type, name) VALUES ('container', $1) RETURNING id::text`, name).Scan(&id); err != nil {
		t.Fatalf("seed artifact %q: %v", name, err)
	}
	return id
}

// seedRetentionSBOM inserts an SBOM ingested s.age ago, with one component so a
// delete's cascade is visible, and returns its id.
func seedRetentionSBOM(t *testing.T, pool *pgxpool.Pool, s retentionSeed) string {
	t.Helper()
	ctx := t.Context()
	var index any
	if s.index != "" {
		index = s.index
	}
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO sbom (spec_version, raw_bom, namespace_id, source_id, artifact_id, subject_version, digest, index_digest, created_at)
		VALUES ('1.6', '{}'::jsonb, $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, now() - $7::interval)
		RETURNING id::text`,
		s.ns, s.source, s.artifact, s.version, s.digest, index, s.age.String()).Scan(&id); err != nil {
		t.Fatalf("seed sbom %s: %v", s.version, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO component (sbom_id, type, name) VALUES ($1::uuid, 'library', 'zlib')`, id); err != nil {
		t.Fatalf("seed component for %s: %v", s.version, err)
	}
	return id
}

// linkScanJob records the registry scan job that produced sbomID, as the
// scanner worker does.
func linkScanJob(t *testing.T, pool *pgxpool.Pool, registryID, repo, digest, sbomID string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO scan_jobs (registry_id, repository, digest, state, sbom_id, nats_msg_id)
		VALUES ($1::uuid, $2, $3, 'succeeded', $4::uuid, $1 || '@' || $3)`,
		registryID, repo, digest, sbomID); err != nil {
		t.Fatalf("link scan job for %s: %v", digest, err)
	}
}

// remainingSBOMs reports which of ids still exist.
func remainingSBOMs(t *testing.T, pool *pgxpool.Pool, ids ...string) []string {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT id::text FROM sbom WHERE id = ANY ($1::uuid[]) ORDER BY id`, ids)
	if err != nil {
		t.Fatalf("listing sboms: %v", err)
	}
	out, err := collectStrings(rows)
	if err != nil {
		t.Fatalf("listing sboms: %v", err)
	}
	return out
}

func collectStrings(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}) ([]string, error) {
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func sorted(ids ...string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

func uuidStrings(t *testing.T, ids []pgtype.UUID) []string {
	t.Helper()
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, uuidString(t, id))
	}
	return sorted(out...)
}

// retentionFixture is a registry and an upload source in the registry's
// namespace.
type retentionFixture struct {
	pool     *pgxpool.Pool
	ns       string
	registry service.Registry
	upload   string
	regSvc   service.RegistryService
	svc      service.RetentionService
}

func newRetentionFixture(t *testing.T) (*retentionFixture, func()) {
	t.Helper()
	requireTestInfra(t)
	pool, cleanDB := setupTestDB(t)
	regSvc := service.NewRegistryService(pool, nil)
	reg, err := regSvc.Create(t.Context(), service.CreateRegistryParams{
		Name: "retention-test", Type: "generic", URL: "registry.example", ScanMode: "poll", PollIntervalMinutes: 60,
	})
	if err != nil {
		cleanDB()
		t.Fatalf("creating registry: %v", err)
	}
	var ns string
	if err := pool.QueryRow(t.Context(), `SELECT namespace_id::text FROM source WHERE id = $1::uuid`, reg.ID).Scan(&ns); err != nil {
		cleanDB()
		t.Fatalf("reading registry namespace: %v", err)
	}
	return &retentionFixture{
		pool: pool, ns: ns, registry: reg, regSvc: regSvc,
		upload: seedSource(t, pool, ns, "upload", "ci"),
		svc:    service.NewRetentionService(pool),
	}, cleanDB
}

const day = 24 * time.Hour

// TestRetentionNewestVersions covers ADR-0056 R3 with P1: keep_last counts
// versions (every platform of a version goes or stays together), the highest
// semver version survives a later backport, max_age prunes within keep_last but
// never the newest version, the cascades leave nothing behind, and dry-run lists
// exactly what Prune then deletes.
func TestRetentionNewestVersions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	is := is.New(t)
	ctx := t.Context()
	f, cleanup := newRetentionFixture(t)
	defer cleanup()

	app := seedRetentionArtifact(t, f.pool, "app")
	seed := func(version, digest string, age time.Duration) string {
		return seedRetentionSBOM(t, f.pool, retentionSeed{ns: f.ns, source: f.upload, artifact: app, version: version, digest: digest, age: age})
	}
	v100amd := seed("v1.0.0", "sha256:a1", 6*day)
	v100arm := seed("v1.0.0", "sha256:a2", 6*day)
	v190 := seed("v1.9.0", "sha256:a3", 5*day)
	v110 := seed("v1.1.0", "sha256:a4", 4*day)
	v120 := seed("v1.2.0", "sha256:a5", 3*day)
	v185 := seed("v1.8.5", "sha256:a6", 2*day) // backport, ingested after v1.9.0
	all := []string{v100amd, v100arm, v190, v110, v120, v185}

	policy := service.RetentionPolicy{KeepLast: 2}
	cands, err := f.svc.Candidates(ctx, policy, 0)
	is.NoErr(err)
	is.Equal(uuidStrings(t, cands.Newest), sorted(v100amd, v100arm, v110))
	is.Equal(len(cands.Window), 0)

	counts, err := f.svc.Prune(ctx, policy, 50)
	is.NoErr(err)
	is.Equal(counts.Newest, int64(3))
	is.Equal(remainingSBOMs(t, f.pool, all...), sorted(v190, v120, v185))

	var orphans int
	is.NoErr(f.pool.QueryRow(ctx, `SELECT count(*) FROM component WHERE sbom_id = ANY ($1::uuid[])`,
		[]string{v100amd, v100arm, v110}).Scan(&orphans))
	is.Equal(orphans, 0)

	counts, err = f.svc.Prune(ctx, policy, 50)
	is.NoErr(err)
	is.Equal(counts.Total(), int64(0)) // nothing left to prune

	t.Run("max age", func(t *testing.T) {
		is := is.New(t)
		ci := seedRetentionArtifact(t, f.pool, "ci-binary")
		older := seedRetentionSBOM(t, f.pool, retentionSeed{ns: f.ns, source: f.upload, artifact: ci, version: "main-aaa", digest: "sha256:b1", age: 10 * day})
		newest := seedRetentionSBOM(t, f.pool, retentionSeed{ns: f.ns, source: f.upload, artifact: ci, version: "main-bbb", digest: "sha256:b2", age: 9 * day})

		counts, err := f.svc.Prune(ctx, service.RetentionPolicy{KeepLast: 20, MaxAge: 7 * day}, 50)
		is.NoErr(err)
		is.Equal(counts.Newest, int64(1))
		is.Equal(remainingSBOMs(t, f.pool, older, newest), []string{newest})
	})
}

// TestRetentionProtected covers ADR-0056 R4 P2 and P3, and R6's check at delete
// time: an image running in another namespace's cluster, and an SBOM with an
// open enrichment job, are never pruned, and a candidate that becomes protected
// after it was listed is skipped by the delete.
func TestRetentionProtected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	is := is.New(t)
	ctx := t.Context()
	f, cleanup := newRetentionFixture(t)
	defer cleanup()

	app := seedRetentionArtifact(t, f.pool, "app")
	seed := func(version, digest, index string, age time.Duration) string {
		return seedRetentionSBOM(t, f.pool, retentionSeed{ns: f.ns, source: f.upload, artifact: app, version: version, digest: digest, index: index, age: age})
	}
	const runningIndex = "sha256:" + "c0ffee" + "0000000000000000000000000000000000000000000000000000000000"
	running := seed("v1", "sha256:c1", runningIndex, 5*day)
	enriching := seed("v2", "sha256:c2", "", 4*day)
	listed := seed("v3", "sha256:c3", "", 3*day)
	seed("v4", "sha256:c4", "", 2*day)
	seed("v5", "sha256:c5", "", day+time.Hour)

	owner := seedUser(t, f.pool, 4242, "other-owner", "member")
	other := seedNamespace(t, f.pool, "other-team", owner, "private")
	cluster := seedCluster(t, f.pool, other, "prod")
	_, err := f.pool.Exec(ctx, `
		INSERT INTO cluster_workload (cluster_id, k8s_namespace, workload_kind, workload_name, container_name, image_ref, image_digest)
		VALUES ($1::uuid, 'default', 'Deployment', 'app', 'app', 'registry.example/app:v1', $2)`, cluster, runningIndex)
	is.NoErr(err)
	_, err = f.pool.Exec(ctx, `INSERT INTO enrichment_jobs (sbom_id, enricher_name, state) VALUES ($1::uuid, 'oci-metadata', 'queued')`, enriching)
	is.NoErr(err)

	// keep_last 2 leaves v1–v3 past the window; P2 and P3 protect v1 and v2.
	q := repository.New(f.pool)
	ids, err := q.ListRetentionNewestCandidates(ctx, repository.ListRetentionNewestCandidatesParams{KeepLast: 2, RowLimit: 50})
	is.NoErr(err)
	is.Equal(uuidStrings(t, ids), []string{listed})

	// v3 picks up an enrichment job after it was listed: the delete skips it.
	_, err = f.pool.Exec(ctx, `INSERT INTO enrichment_jobs (sbom_id, enricher_name, state) VALUES ($1::uuid, 'git', 'running')`, listed)
	is.NoErr(err)
	n, err := q.DeleteRetentionBatch(ctx, ids)
	is.NoErr(err)
	is.Equal(n, int64(0))
	is.Equal(remainingSBOMs(t, f.pool, running, enriching, listed), sorted(running, enriching, listed))
}

// TestRetentionRegistryWindow covers ADR-0056 R2: a registry SBOM whose image
// the last successful walk did not select is pruned. Every platform of a
// selected index stays, a failed walk leaves the window alone, a repository the
// walk did not cover keeps its SBOMs, a fresh SBOM is protected (P3), and class
// N never touches registry SBOMs.
func TestRetentionRegistryWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	is := is.New(t)
	ctx := t.Context()
	f, cleanup := newRetentionFixture(t)
	defer cleanup()

	img := seedRetentionArtifact(t, f.pool, "registry.example/app")
	seed := func(repo, version, digest, index string, age time.Duration) string {
		id := seedRetentionSBOM(t, f.pool, retentionSeed{ns: f.ns, source: f.registry.ID, artifact: img, version: version, digest: digest, index: index, age: age})
		linkScanJob(t, f.pool, f.registry.ID, repo, digest, id)
		return id
	}
	inWindow := seed("app", "1.1.0", "sha256:d1", "", 3*day)
	platform := seed("app", "1.2.0", "sha256:d2-arm64", "sha256:i2", 3*day)
	outOfWindow := seed("app", "1.0.0", "sha256:d3", "", 5*day)
	fresh := seed("app", "0.9.0", "sha256:d4", "", time.Hour)
	newest := seed("app", "1.3.0", "sha256:d5", "", 30*time.Minute)
	uncovered := seed("gone", "0.1.0", "sha256:d6", "", 5*day)
	all := []string{inWindow, platform, outOfWindow, fresh, newest, uncovered}

	is.NoErr(f.regSvc.RecordWalkStats(ctx, f.registry.ID, service.WalkStats{
		At:      time.Now().UTC(),
		Windows: map[string][]string{"app": {"sha256:d1", "sha256:i2", "sha256:d5"}},
	}))
	// A failed walk keeps the last successful walk's window.
	is.NoErr(f.regSvc.RecordWalkStats(ctx, f.registry.ID, service.WalkStats{
		At: time.Now().UTC(), Error: "listing catalog: 503", Windows: map[string][]string{"app": {}},
	}))

	// Class N skips registry SBOMs, however many versions the series has.
	counts, err := f.svc.Prune(ctx, service.RetentionPolicy{KeepLast: 2}, 50)
	is.NoErr(err)
	is.Equal(counts.Total(), int64(0))

	counts, err = f.svc.Prune(ctx, service.RetentionPolicy{RegistryWindow: true}, 50)
	is.NoErr(err)
	is.Equal(counts.Window, int64(1))
	is.Equal(remainingSBOMs(t, f.pool, all...), sorted(inWindow, platform, fresh, newest, uncovered))
}

// TestRetentionSweepIsLeaderElected covers ADR-0056 R6: two sweepers against
// one database contend for the retention lock, only one of them sweeps, and the
// sweep it runs deletes the backlog.
func TestRetentionSweepIsLeaderElected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	is := is.New(t)
	f, cleanup := newRetentionFixture(t)
	defer cleanup()

	app := seedRetentionArtifact(t, f.pool, "app")
	ids := make([]string, 0, 5)
	for i := range 5 {
		ids = append(ids, seedRetentionSBOM(t, f.pool, retentionSeed{
			ns: f.ns, source: f.upload, artifact: app,
			version: fmt.Sprintf("v1.%d.0", i), digest: fmt.Sprintf("sha256:e%d", i), age: time.Duration(10-i) * day,
		}))
	}

	ctx, cancel := context.WithCancel(t.Context())
	var started atomic.Int32
	swept := make(chan struct{}, 2)
	const key = int64(0x0c1de5)
	for range 2 {
		sweeper := service.NewRetentionSweeper(service.NewRetentionService(f.pool),
			service.RetentionPolicy{KeepLast: 2}, false, time.Hour, 50, nil)
		go service.LeaderElect(ctx, f.pool, key, func(ctx context.Context) {
			started.Add(1)
			_, _ = sweeper.Sweep(ctx)
			swept <- struct{}{}
			<-ctx.Done()
		})
	}

	select {
	case <-swept:
	case <-time.After(30 * time.Second):
		t.Fatal("no sweeper ran")
	}
	time.Sleep(time.Second) // the loser has had its try at the lock by now
	is.Equal(started.Load(), int32(1))
	is.Equal(remainingSBOMs(t, f.pool, ids...), sorted(ids[3], ids[4]))
	cancel()
}
