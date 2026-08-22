package tests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
	"github.com/pressly/goose/v3"

	"github.com/pfenerty/ocidex/db"
	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/service"
)

// clusterMigrationVersion is the goose version of 00059_cluster_workload.sql.
// Pinned so the round-trip test below keeps testing this migration after later
// ones are added.
const clusterMigrationVersion = 59

// digest builds a well-formed sha256 digest from a single hex character, so the
// tests can name digests readably without 64-character literals everywhere.
func digest(c byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = c
	}
	return "sha256:" + string(out)
}

func txt(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

func mustUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatalf("parsing uuid %q: %v", s, err)
	}
	return u
}

// seedCluster inserts a cluster owned by namespaceID.
func seedCluster(t *testing.T, pool *pgxpool.Pool, namespaceID, name string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(t.Context(), `
		INSERT INTO cluster (namespace_id, name)
		VALUES ($1, $2)
		RETURNING id::text
	`, namespaceID, name).Scan(&id)
	if err != nil {
		t.Fatalf("seed cluster %q: %v", name, err)
	}
	return id
}

// seedArtifactSBOM inserts an artifact and one SBOM for it carrying the given
// digest and index digest, returning the artifact id. index is optional — pass
// "" for a single-arch image.
func seedArtifactSBOM(t *testing.T, pool *pgxpool.Pool, nsID, name, dgst, index string) string {
	t.Helper()
	ctx := t.Context()
	var artifactID string
	err := pool.QueryRow(ctx, `
		INSERT INTO artifact (type, name) VALUES ('container', $1) RETURNING id::text
	`, name).Scan(&artifactID)
	if err != nil {
		t.Fatalf("seed artifact %q: %v", name, err)
	}

	var idx any
	if index != "" {
		idx = index
	}
	var sbomID string
	err = pool.QueryRow(ctx, `
		INSERT INTO sbom (spec_version, raw_bom, digest, index_digest, artifact_id, namespace_id, subject_version)
		VALUES ('1.6', '{}'::jsonb, $1, $2, $3::uuid, $4::uuid, '1.0.0')
		RETURNING id::text
	`, dgst, idx, artifactID, nsID).Scan(&sbomID)
	if err != nil {
		t.Fatalf("seed sbom for %q: %v", name, err)
	}
	return artifactID
}

// TestClusterMigrationRoundTrip proves 00059 rolls back and re-applies cleanly,
// which is the only part of the schema story that a query-level test cannot
// reach: sqlc validates the up direction implicitly by generating against it,
// but nothing else ever executes the down.
func TestClusterMigrationRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	connStr, dropDB := newTestDB(t)
	defer dropDB()
	migrateDB(t, connStr)

	sqlDB, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("opening migration connection: %v", err)
	}
	defer sqlDB.Close()

	goose.SetBaseFS(db.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("setting dialect: %v", err)
	}

	tablesExist := func() bool {
		var exists bool
		if err := sqlDB.QueryRow(`
			SELECT to_regclass('public.cluster') IS NOT NULL
			   AND to_regclass('public.cluster_workload') IS NOT NULL
		`).Scan(&exists); err != nil {
			t.Fatalf("checking cluster tables: %v", err)
		}
		return exists
	}

	is := is.New(t)
	is.True(tablesExist())

	// DownTo the version *below* this migration rather than a bare Down: a bare
	// Down rolls back whatever happens to be last, so the next migration added to
	// the tree would silently make this test assert on someone else's schema.
	if err := goose.DownTo(sqlDB, "migrations", clusterMigrationVersion-1); err != nil {
		t.Fatalf("rolling back: %v", err)
	}
	is.Equal(tablesExist(), false)

	if err := goose.Up(sqlDB, "migrations"); err != nil {
		t.Fatalf("re-applying: %v", err)
	}
	is.True(tablesExist())
}

// TestClusterWorkloadDigestJoin covers the four match states of ADR-044 K5 in
// one snapshot, because the states only mean anything relative to each other:
// the bug this guards against is any of them collapsing into "matched, clean".
func TestClusterWorkloadDigestJoin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	owner := seedUser(t, pool, 9001, "cluster-owner", "member")
	nsID := seedNamespace(t, pool, "cluster-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "prod")

	exactDigest := digest('a')
	childDigest := digest('b')
	indexDigest := digest('c')
	unknownDigest := digest('d')

	// Single-arch image: kubelet reports the manifest digest we scanned.
	exactArtifact := seedArtifactSBOM(t, pool, nsID, "docker.io/exact", exactDigest, "")
	// Multi-arch image: we hold the per-platform SBOM, but the kubelet reports
	// the *index* digest, which is the case a strict sbom.digest join misses.
	indexArtifact := seedArtifactSBOM(t, pool, nsID, "docker.io/multi", childDigest, indexDigest)

	observed := time.Now().UTC()
	upsert := func(name, dgst string, pods int32) {
		t.Helper()
		var d pgtype.Text
		if dgst != "" {
			d = txt(dgst)
		}
		err := q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID:     mustUUID(t, clusterID),
			K8sNamespace:  "default",
			WorkloadKind:  "Deployment",
			WorkloadName:  name,
			ContainerName: "app",
			ImageRef:      name + ":latest",
			ImageDigest:   d,
			PodCount:      pods,
			ObservedAt:    pgtype.Timestamptz{Time: observed, Valid: true},
		})
		if err != nil {
			t.Fatalf("upsert %q: %v", name, err)
		}
	}

	upsert("exact-app", exactDigest, 3)
	upsert("index-app", indexDigest, 2)
	upsert("unknown-app", unknownDigest, 1)
	upsert("unresolvable-app", "", 1)

	rows, err := q.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
		ClusterID: mustUUID(t, clusterID),
		UserID:    owner,
		IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("listing workloads: %v", err)
	}
	is.Equal(len(rows), 4)

	byName := map[string]repository.ListClusterWorkloadsRow{}
	for _, r := range rows {
		byName[r.ClusterWorkload.WorkloadName] = r
	}

	is.Equal(byName["exact-app"].MatchState, "exact")
	is.Equal(byName["exact-app"].ArtifactID, mustUUID(t, exactArtifact))

	// The whole reason the join has a second tier: this row would be "unknown"
	// if we only compared against sbom.digest.
	is.Equal(byName["index-app"].MatchState, "index")
	is.Equal(byName["index-app"].ArtifactID, mustUUID(t, indexArtifact))

	// A real digest we have never been given an SBOM for: a coverage gap, and it
	// must not carry an artifact.
	is.Equal(byName["unknown-app"].MatchState, "unknown")
	is.Equal(byName["unknown-app"].ArtifactID.Valid, false)

	// No digest at all: an agent/runtime gap, reported separately from the
	// coverage gap because the remedy differs.
	is.Equal(byName["unresolvable-app"].MatchState, "unresolvable")
	is.Equal(byName["unresolvable-app"].ClusterWorkload.ImageDigest.Valid, false)

	cov, err := q.GetClusterWorkloadCoverage(ctx, repository.GetClusterWorkloadCoverageParams{
		ClusterID: mustUUID(t, clusterID),
		UserID:    owner,
		IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	is.Equal(cov.Total, int64(4))
	is.Equal(cov.Matched, int64(2))
	is.Equal(cov.Unknown, int64(1))
	is.Equal(cov.Unresolvable, int64(1))
	// Pods is a second figure beside the four match-state counts, never a
	// replacement for them: 3 + 2 + 1 + 1 replicas across those four rows.
	is.Equal(cov.Pods, int64(7))
}

// TestClusterWorkloadSnapshotReplaces proves K7's full-snapshot semantics: a
// second snapshot must prune what it no longer reports, and must not restart
// first_seen_at for what it still does.
func TestClusterWorkloadSnapshotReplaces(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	owner := seedUser(t, pool, 9002, "snapshot-owner", "member")
	nsID := seedNamespace(t, pool, "snapshot-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "prod")
	cid := mustUUID(t, clusterID)

	first := time.Now().UTC().Add(-time.Hour)
	second := time.Now().UTC()

	upsert := func(name, dgst string, pods int32, at time.Time) {
		t.Helper()
		err := q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID:     cid,
			K8sNamespace:  "default",
			WorkloadKind:  "Deployment",
			WorkloadName:  name,
			ContainerName: "app",
			ImageRef:      name + ":latest",
			ImageDigest:   txt(dgst),
			PodCount:      pods,
			ObservedAt:    pgtype.Timestamptz{Time: at, Valid: true},
		})
		if err != nil {
			t.Fatalf("upsert %q: %v", name, err)
		}
	}

	// Snapshot 1: two workloads.
	upsert("stays", digest('a'), 2, first)
	upsert("goes-away", digest('b'), 1, first)
	pruned, err := q.PruneClusterWorkloads(ctx, repository.PruneClusterWorkloadsParams{
		ClusterID: cid, ObservedAt: pgtype.Timestamptz{Time: first, Valid: true},
	})
	if err != nil {
		t.Fatalf("prune 1: %v", err)
	}
	is.Equal(pruned, int64(0))

	var firstSeen time.Time
	if err := pool.QueryRow(ctx,
		`SELECT first_seen_at FROM cluster_workload WHERE workload_name = 'stays'`,
	).Scan(&firstSeen); err != nil {
		t.Fatalf("reading first_seen_at: %v", err)
	}

	// Snapshot 2: "stays" scaled up, "goes-away" gone, "new" appeared.
	upsert("stays", digest('a'), 5, second)
	upsert("new", digest('c'), 1, second)
	pruned, err = q.PruneClusterWorkloads(ctx, repository.PruneClusterWorkloadsParams{
		ClusterID: cid, ObservedAt: pgtype.Timestamptz{Time: second, Valid: true},
	})
	if err != nil {
		t.Fatalf("prune 2: %v", err)
	}
	is.Equal(pruned, int64(1))

	rows, err := q.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
		ClusterID: cid,
		UserID:    owner,
		IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	is.Equal(len(rows), 2)

	byName := map[string]repository.ListClusterWorkloadsRow{}
	for _, r := range rows {
		byName[r.ClusterWorkload.WorkloadName] = r
	}
	_, gone := byName["goes-away"]
	is.Equal(gone, false)
	is.Equal(byName["stays"].ClusterWorkload.PodCount, int32(5))
	// "running since" is the only history this table keeps, so re-reporting must
	// not reset it.
	is.Equal(byName["stays"].ClusterWorkload.FirstSeenAt.Time.UTC(), firstSeen.UTC())

	// A rollout: the same container at a second digest is a second row, not an
	// overwrite. Collapsing them would hide the half still carrying the old image.
	upsert("stays", digest('a'), 3, second)
	upsert("stays", digest('e'), 2, second)
	rows, err = q.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
		ClusterID: cid,
		UserID:    owner,
		IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("listing after rollout: %v", err)
	}
	staysRows := 0
	for _, r := range rows {
		if r.ClusterWorkload.WorkloadName == "stays" {
			staysRows++
		}
	}
	is.Equal(staysRows, 2)
}

// TestClusterVisibility proves a cluster in a namespace the caller cannot see is
// absent from every read path, not merely from the listing.
func TestClusterVisibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	owner := seedUser(t, pool, 9003, "vis-owner", "member")
	outsider := seedUser(t, pool, 9004, "vis-outsider", "member")

	privateNS := seedNamespace(t, pool, "vis-private", owner, "private")
	publicNS := seedNamespace(t, pool, "vis-public", owner, "public")
	privateCluster := seedCluster(t, pool, privateNS, "private-prod")
	seedCluster(t, pool, publicNS, "public-prod")

	err := q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
		ClusterID:     mustUUID(t, privateCluster),
		K8sNamespace:  "default",
		WorkloadKind:  "Deployment",
		WorkloadName:  "secret-app",
		ContainerName: "app",
		ImageRef:      "secret:latest",
		ImageDigest:   txt(digest('a')),
		PodCount:      1,
		ObservedAt:    pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	listFor := func(u pgtype.UUID, ownedOnly bool) []repository.ListClustersRow {
		t.Helper()
		rows, err := q.ListClusters(ctx, repository.ListClustersParams{
			OwnedOnly: pgtype.Bool{Bool: ownedOnly, Valid: true},
			UserID:    u,
			IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
		})
		if err != nil {
			t.Fatalf("listing clusters: %v", err)
		}
		return rows
	}

	// The owner sees both of theirs; an outsider sees only the public one.
	is.Equal(len(listFor(owner, false)), 2)
	is.Equal(len(listFor(outsider, false)), 1)
	is.Equal(listFor(outsider, false)[0].Cluster.Name, "public-prod")

	// An unauthenticated caller gets the public set, never the private cluster.
	is.Equal(len(listFor(pgtype.UUID{}, false)), 1)

	// The workload list is gated on the cluster's namespace, so knowing the
	// cluster id is not enough — this is the check that stops an id leak from
	// becoming a data leak.
	rows, err := q.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
		ClusterID: mustUUID(t, privateCluster),
		UserID:    outsider,
		IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("listing workloads as outsider: %v", err)
	}
	is.Equal(len(rows), 0)

	// The owner does see it, proving the empty result above is the filter and
	// not a broken query.
	rows, err = q.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
		ClusterID: mustUUID(t, privateCluster),
		UserID:    owner,
		IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("listing workloads as owner: %v", err)
	}
	is.Equal(len(rows), 1)

	// An admin sees everything, from the same query.
	adminRows, err := q.ListClusters(ctx, repository.ListClustersParams{
		OwnedOnly: pgtype.Bool{Bool: false, Valid: true},
		UserID:    outsider,
		IsAdmin:   pgtype.Bool{Bool: true, Valid: true},
	})
	if err != nil {
		t.Fatalf("listing as admin: %v", err)
	}
	is.Equal(len(adminRows), 2)

	// owned_only is strictly narrower: it drops others' public rows.
	is.Equal(len(listFor(outsider, true)), 0)
}

// seedSBOMWithPurl inserts an artifact, an SBOM at the given digest, and one
// component carrying purl.
func seedSBOMWithPurl(t *testing.T, pool *pgxpool.Pool, nsID, name, dgst, purl string) {
	t.Helper()
	ctx := t.Context()
	var artifactID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO artifact (type, name) VALUES ('container', $1) RETURNING id::text
	`, name).Scan(&artifactID); err != nil {
		t.Fatalf("seed artifact %q: %v", name, err)
	}
	var sbomID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO sbom (spec_version, raw_bom, digest, artifact_id, namespace_id, subject_version)
		VALUES ('1.6', '{}'::jsonb, $1, $2::uuid, $3::uuid, '1.0.0')
		RETURNING id::text
	`, dgst, artifactID, nsID).Scan(&sbomID); err != nil {
		t.Fatalf("seed sbom for %q: %v", name, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component (sbom_id, type, name, version, purl)
		VALUES ($1::uuid, 'library', 'lib', '1.0.0', $2)
	`, sbomID, purl); err != nil {
		t.Fatalf("seed component for %q: %v", name, err)
	}
}

// seedAdvisory inserts one vulnerability record and links it to purl. id is the
// native advisory id; canonical is what it aliases to.
func seedAdvisory(t *testing.T, pool *pgxpool.Pool, id, canonical, severity string, score float32, purl string) {
	t.Helper()
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerability (id, aliases, canonical_id, severity, cvss_score, summary)
		VALUES ($1, ARRAY[$2]::text[], $2, $3, $4, 'seeded')
	`, id, canonical, severity, score); err != nil {
		t.Fatalf("seed vulnerability %q: %v", id, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO package_vulnerability (purl, vulnerability_id) VALUES ($1, $2)
	`, purl, id); err != nil {
		t.Fatalf("link %q to %q: %v", id, purl, err)
	}
}

// TestClusterRunningVulns covers the two properties the cluster vulnerability
// drill-down rests on, neither of which is visible from a single-advisory
// fixture:
//
//   - aliased advisories collapse to one row, because OSV publishes the same
//     finding as GO-… and GHSA-… both pointing at one CVE, and listing each
//     separately would report one problem twice;
//   - the workload count is DISTINCT across the whole alias group and across
//     components, so it is a number of things to go and fix.
//
// The reverse lookup is asserted from the same fixture: the two directions
// disagreeing is precisely the bug that makes a drill-down untrustworthy.
func TestClusterRunningVulns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	owner := seedUser(t, pool, 9101, "vuln-cluster-owner", "member")
	nsID := seedNamespace(t, pool, "vuln-cluster-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "prod")

	runningDigest := digest('a')
	otherDigest := digest('b')
	unknownDigest := digest('c')

	const (
		vulnPurl  = "pkg:golang/example.com/vulnerable@1.0.0"
		cleanPurl = "pkg:golang/example.com/clean@1.0.0"
	)

	seedSBOMWithPurl(t, pool, nsID, "docker.io/api", runningDigest, vulnPurl)
	seedSBOMWithPurl(t, pool, nsID, "docker.io/web", otherDigest, vulnPurl)
	seedSBOMWithPurl(t, pool, nsID, "docker.io/idle", digest('d'), cleanPurl)

	// Two native records aliasing one CVE, plus an unrelated lower-severity one.
	seedAdvisory(t, pool, "GHSA-aaaa", "CVE-2026-0001", "CRITICAL", 9.8, vulnPurl)
	seedAdvisory(t, pool, "GO-2026-0001", "CVE-2026-0001", "HIGH", 7.5, vulnPurl)
	seedAdvisory(t, pool, "GHSA-bbbb", "CVE-2026-0002", "LOW", 3.1, vulnPurl)

	observed := pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	upsert := func(ns, name, dgst string, pods int32) {
		t.Helper()
		var d pgtype.Text
		if dgst != "" {
			d = txt(dgst)
		}
		if err := q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID:     mustUUID(t, clusterID),
			K8sNamespace:  ns,
			WorkloadKind:  "Deployment",
			WorkloadName:  name,
			ContainerName: "app",
			ImageRef:      name + ":latest",
			ImageDigest:   d,
			PodCount:      pods,
			ObservedAt:    observed,
		}); err != nil {
			t.Fatalf("upsert %q: %v", name, err)
		}
	}
	upsert("default", "api", runningDigest, 3)
	upsert("frontend", "web", otherDigest, 1)
	upsert("batch", "orphan", unknownDigest, 1) // no SBOM: contributes no findings

	cid := mustUUID(t, clusterID)
	admin := pgtype.Bool{Bool: true, Valid: true}
	page := func(severity pgtype.Text, limit, offset int32) []repository.ListClusterRunningVulnsRow {
		t.Helper()
		rows, err := q.ListClusterRunningVulns(ctx, repository.ListClusterRunningVulnsParams{
			ClusterID: cid,
			Severity:  severity,
			Limit:     pgtype.Int4{Int32: limit, Valid: true},
			Offset:    pgtype.Int4{Int32: offset, Valid: true},
			IsAdmin:   admin,
		})
		if err != nil {
			t.Fatalf("listing running vulns: %v", err)
		}
		return rows
	}

	t.Run("aliases collapse and workloads are counted distinctly", func(t *testing.T) {
		is := is.New(t)
		rows := page(pgtype.Text{}, 20, 0)
		is.Equal(len(rows), 2) // CVE-2026-0001 once, not twice, plus CVE-2026-0002

		is.Equal(rows[0].CanonicalID, "CVE-2026-0001") // most severe first
		is.Equal(rows[0].Severity.String, "CRITICAL")  // representative is the worst of the group
		is.Equal(rows[0].WorkloadCount, int64(2))      // api and web; orphan has no SBOM
		is.Equal(rows[1].CanonicalID, "CVE-2026-0002")
		is.Equal(rows[1].WorkloadCount, int64(2))

		total, err := q.CountClusterRunningVulns(ctx, repository.CountClusterRunningVulnsParams{
			ClusterID: cid,
			IsAdmin:   admin,
		})
		is.NoErr(err)
		is.Equal(total, int64(2)) // the total counts rows as the page does
	})

	t.Run("severity filter and paging agree with the total", func(t *testing.T) {
		is := is.New(t)
		rows := page(txt("CRITICAL"), 20, 0)
		is.Equal(len(rows), 1)
		is.Equal(rows[0].CanonicalID, "CVE-2026-0001")

		total, err := q.CountClusterRunningVulns(ctx, repository.CountClusterRunningVulnsParams{
			ClusterID: cid,
			Severity:  txt("CRITICAL"),
			IsAdmin:   admin,
		})
		is.NoErr(err)
		is.Equal(total, int64(1))

		is.Equal(len(page(pgtype.Text{}, 1, 0)), 1)
		second := page(pgtype.Text{}, 1, 1)
		is.Equal(len(second), 1)
		is.Equal(second[0].CanonicalID, "CVE-2026-0002") // offset advanced, no repeat
	})

	t.Run("reverse lookup agrees with the forward count", func(t *testing.T) {
		is := is.New(t)
		rows, err := q.ListWorkloadsForVulnerability(ctx, repository.ListWorkloadsForVulnerabilityParams{
			CanonicalID: "CVE-2026-0001",
			ClusterID:   cid,
			Limit:       pgtype.Int4{Int32: 50, Valid: true},
			IsAdmin:     admin,
		})
		is.NoErr(err)
		is.Equal(len(rows), 2)

		names := map[string]string{}
		for _, r := range rows {
			names[r.ClusterWorkload.WorkloadName] = r.MatchState
			is.Equal(r.ClusterName, "prod")
		}
		is.Equal(names["api"], "exact")
		is.Equal(names["web"], "exact")
		_, orphaned := names["orphan"]
		is.True(!orphaned)

		// Reached through the sibling alias, the answer must be the same set —
		// a workload is affected by the finding, not by the id it was filed under.
		byAlias, err := q.ListWorkloadsForVulnerability(ctx, repository.ListWorkloadsForVulnerabilityParams{
			CanonicalID: "CVE-2026-0001",
			Limit:       pgtype.Int4{Int32: 50, Valid: true},
			IsAdmin:     admin,
		})
		is.NoErr(err)
		is.Equal(len(byAlias), 2) // cluster_id omitted: every visible cluster
	})

	t.Run("an invisible namespace yields nothing", func(t *testing.T) {
		is := is.New(t)
		stranger := seedUser(t, pool, 9102, "vuln-cluster-stranger", "member")
		rows, err := q.ListClusterRunningVulns(ctx, repository.ListClusterRunningVulnsParams{
			ClusterID: cid,
			Limit:     pgtype.Int4{Int32: 20, Valid: true},
			Offset:    pgtype.Int4{Int32: 0, Valid: true},
			UserID:    stranger,
			IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
		})
		is.NoErr(err)
		is.Equal(len(rows), 0)
	})
}

// TestClusterWorkloadFilters covers the filter, paging and facet story: the
// filters must agree with the count that pages them, the facet list must
// describe the whole cluster rather than the current page, and coverage must
// stay cluster-wide no matter what the table is filtered to (ADR-044 K5).
func TestClusterWorkloadFilters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	owner := seedUser(t, pool, 9401, "filter-owner", "member")
	nsID := seedNamespace(t, pool, "filter-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "filter-prod")
	admin := pgtype.Bool{Bool: false, Valid: true}
	cid := mustUUID(t, clusterID)

	matchedDigest := digest('a')
	seedArtifactSBOM(t, pool, nsID, "docker.io/api", matchedDigest, "")

	observed := time.Now().UTC()
	upsert := func(k8sNS, name, container, ref, dgst string) {
		t.Helper()
		var d pgtype.Text
		if dgst != "" {
			d = txt(dgst)
		}
		err := q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID:     cid,
			K8sNamespace:  k8sNS,
			WorkloadKind:  "Deployment",
			WorkloadName:  name,
			ContainerName: container,
			ImageRef:      ref,
			ImageDigest:   d,
			PodCount:      1,
			ObservedAt:    pgtype.Timestamptz{Time: observed, Valid: true},
		})
		if err != nil {
			t.Fatalf("upsert %q: %v", name, err)
		}
	}

	upsert("prod", "api", "app", "docker.io/api:v1", matchedDigest)
	upsert("prod", "worker", "app", "docker.io/worker:v1", digest('b'))
	upsert("prod", "cache", "redis", "docker.io/redis:7", digest('c'))
	upsert("staging", "api", "app", "docker.io/api:v2", matchedDigest)
	upsert("staging", "legacy", "app", "docker.io/legacy:v1", "")

	list := func(p repository.ListClusterWorkloadsParams) []repository.ListClusterWorkloadsRow {
		t.Helper()
		p.ClusterID, p.UserID, p.IsAdmin = cid, owner, admin
		rows, err := q.ListClusterWorkloads(ctx, p)
		if err != nil {
			t.Fatalf("listing workloads: %v", err)
		}
		return rows
	}
	count := func(p repository.CountClusterWorkloadsParams) int64 {
		t.Helper()
		p.ClusterID, p.UserID, p.IsAdmin = cid, owner, admin
		total, err := q.CountClusterWorkloads(ctx, p)
		if err != nil {
			t.Fatalf("counting workloads: %v", err)
		}
		return total
	}

	t.Run("namespace filter", func(t *testing.T) {
		is := is.New(t)
		rows := list(repository.ListClusterWorkloadsParams{K8sNamespace: txt("staging")})
		is.Equal(len(rows), 2)
		is.Equal(count(repository.CountClusterWorkloadsParams{K8sNamespace: txt("staging")}), int64(2))
	})

	// The filter reads the same computed state the column projects. A second
	// copy of the CASE is what this asserts against: if the two ever disagree,
	// the filtered rows would carry a state the filter did not ask for.
	t.Run("match state filter agrees with the projected column", func(t *testing.T) {
		is := is.New(t)
		for state, want := range map[string]int64{"exact": 2, "unknown": 2, "unresolvable": 1, "index": 0} {
			rows := list(repository.ListClusterWorkloadsParams{MatchState: txt(state)})
			is.Equal(int64(len(rows)), want)
			is.Equal(count(repository.CountClusterWorkloadsParams{MatchState: txt(state)}), want)
			for _, r := range rows {
				is.Equal(r.MatchState, state)
			}
		}
	})

	t.Run("q matches workload, container and image ref", func(t *testing.T) {
		is := is.New(t)
		// Matches two workload names.
		is.Equal(count(repository.CountClusterWorkloadsParams{Q: txt("api")}), int64(2))
		// Matches a container name no workload name contains.
		is.Equal(count(repository.CountClusterWorkloadsParams{Q: txt("redis")}), int64(1))
		// Matches an image tag that appears in no name at all.
		is.Equal(count(repository.CountClusterWorkloadsParams{Q: txt(":v2")}), int64(1))
	})

	t.Run("filters compose", func(t *testing.T) {
		is := is.New(t)
		p := repository.ListClusterWorkloadsParams{K8sNamespace: txt("prod"), MatchState: txt("unknown")}
		rows := list(p)
		is.Equal(len(rows), 2)
		is.Equal(count(repository.CountClusterWorkloadsParams{K8sNamespace: p.K8sNamespace, MatchState: p.MatchState}), int64(2))
	})

	// Offset paging over a stable ordering: the pages must partition the list,
	// not overlap it.
	t.Run("paging partitions the list", func(t *testing.T) {
		is := is.New(t)
		total := count(repository.CountClusterWorkloadsParams{})
		is.Equal(total, int64(5))

		var seen []string
		for offset := int32(0); offset < int32(total); offset += 2 {
			page := list(repository.ListClusterWorkloadsParams{
				Limit:  pgtype.Int4{Int32: 2, Valid: true},
				Offset: pgtype.Int4{Int32: offset, Valid: true},
			})
			for _, r := range page {
				seen = append(seen, r.ClusterWorkload.K8sNamespace+"/"+r.ClusterWorkload.WorkloadName)
			}
		}
		is.Equal(len(seen), 5)
		is.Equal(seen, []string{"prod/api", "prod/cache", "prod/worker", "staging/api", "staging/legacy"})
	})

	// The facet is the reason a separate query exists: page one holds only
	// "prod", so a client deriving the filter from its rows would never offer
	// "staging".
	t.Run("namespace facets cover the cluster, not the page", func(t *testing.T) {
		is := is.New(t)
		facets, err := q.ListClusterK8sNamespaces(ctx, repository.ListClusterK8sNamespacesParams{
			ClusterID: cid, UserID: owner, IsAdmin: admin,
		})
		if err != nil {
			t.Fatalf("listing namespaces: %v", err)
		}
		is.Equal(len(facets), 2)
		is.Equal(facets[0].K8sNamespace, "prod")
		is.Equal(facets[0].WorkloadCount, int64(3))
		is.Equal(facets[1].K8sNamespace, "staging")
		is.Equal(facets[1].WorkloadCount, int64(2))
	})

	// Coverage takes no filters at all: whatever the table is showing, the
	// denominator is the whole cluster.
	t.Run("coverage stays cluster-wide", func(t *testing.T) {
		is := is.New(t)
		cov, err := q.GetClusterWorkloadCoverage(ctx, repository.GetClusterWorkloadCoverageParams{
			ClusterID: cid, UserID: owner, IsAdmin: admin,
		})
		if err != nil {
			t.Fatalf("coverage: %v", err)
		}
		is.Equal(cov.Total, int64(5))
		is.Equal(cov.Matched, int64(2))
		is.Equal(cov.Unknown, int64(2))
		is.Equal(cov.Unresolvable, int64(1))
	})

	// Visibility is enforced inside the filtered queries too, not only in the
	// unfiltered ones.
	t.Run("invisible to another member", func(t *testing.T) {
		is := is.New(t)
		other := seedUser(t, pool, 9402, "filter-outsider", "member")
		rows, err := q.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
			ClusterID: cid, UserID: other, IsAdmin: admin, MatchState: txt("exact"),
		})
		if err != nil {
			t.Fatalf("listing workloads: %v", err)
		}
		is.Equal(len(rows), 0)

		facets, err := q.ListClusterK8sNamespaces(ctx, repository.ListClusterK8sNamespacesParams{
			ClusterID: cid, UserID: other, IsAdmin: admin,
		})
		if err != nil {
			t.Fatalf("listing namespaces: %v", err)
		}
		is.Equal(len(facets), 0)
	})
}

// TestClusterWorkloadVulnCountsAndSort covers the two things that make the
// workload table answer "which images have vulnerabilities": the per-row
// severity counts, and the vuln_count sort that ranks by them.
func TestClusterWorkloadVulnCountsAndSort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)
	svc := service.NewClusterService(pool)

	owner := seedUser(t, pool, 9501, "vulncount-owner", "member")
	nsID := seedNamespace(t, pool, "vulncount-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "vulncount-prod")
	admin := pgtype.Bool{Bool: false, Valid: true}
	cid := mustUUID(t, clusterID)

	riskyDigest, cleanDigest := digest('a'), digest('b')
	seedSBOMWithPurl(t, pool, nsID, "docker.io/risky", riskyDigest, "pkg:deb/debian/openssl@3.0.1")
	seedSBOMWithPurl(t, pool, nsID, "docker.io/clean", cleanDigest, "pkg:deb/debian/tzdata@2024a")

	// Two ids aliasing one CVE plus a distinct HIGH: the alias group must count
	// once, so this image carries one critical and one high, not two and one.
	seedAdvisory(t, pool, "GO-2024-0001", "CVE-2024-1111", "CRITICAL", 9.8, "pkg:deb/debian/openssl@3.0.1")
	seedAdvisory(t, pool, "GHSA-aaaa-bbbb-cccc", "CVE-2024-1111", "CRITICAL", 9.8, "pkg:deb/debian/openssl@3.0.1")
	seedAdvisory(t, pool, "GO-2024-0002", "CVE-2024-2222", "HIGH", 7.5, "pkg:deb/debian/openssl@3.0.1")

	observed := time.Now().UTC()
	upsert := func(name, ref, dgst string) {
		t.Helper()
		var d pgtype.Text
		if dgst != "" {
			d = txt(dgst)
		}
		err := q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID:     cid,
			K8sNamespace:  "prod",
			WorkloadKind:  "Deployment",
			WorkloadName:  name,
			ContainerName: "app",
			ImageRef:      ref,
			ImageDigest:   d,
			PodCount:      1,
			ObservedAt:    pgtype.Timestamptz{Time: observed, Valid: true},
		})
		if err != nil {
			t.Fatalf("upsert %q: %v", name, err)
		}
	}

	// Names are deliberately in the opposite order to their risk, so a sort by
	// vuln_count cannot pass by accidentally reproducing the default ordering.
	upsert("a-clean", "docker.io/clean:v1", cleanDigest)
	upsert("b-risky", "docker.io/risky:v1", riskyDigest)
	upsert("c-unmatched", "docker.io/mystery:v1", digest('c'))

	vis := service.VisibilityFilter{UserID: owner}

	t.Run("counts are per severity and deduplicated by canonical id", func(t *testing.T) {
		is := is.New(t)
		rows, err := q.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
			ClusterID: cid, UserID: owner, IsAdmin: admin, Q: txt("b-risky"),
		})
		if err != nil {
			t.Fatalf("listing workloads: %v", err)
		}
		is.Equal(len(rows), 1)
		is.Equal(rows[0].CriticalCount, int64(1))
		is.Equal(rows[0].HighCount, int64(1))
		is.Equal(rows[0].MediumCount, int64(0))
		is.Equal(rows[0].LowCount, int64(0))
	})

	// The distinction ADR-044 K5 exists for: an image nobody assessed must not
	// report the same "no findings" a scanned image with none reports.
	t.Run("unassessed carries no counts, assessed and clean carries zeros", func(t *testing.T) {
		is := is.New(t)
		result, err := svc.ListWorkloads(ctx, clusterID, service.WorkloadParams{}, vis)
		if err != nil {
			t.Fatalf("listing workloads: %v", err)
		}
		is.Equal(len(result.Data), 3)

		byName := map[string]service.ClusterWorkload{}
		for _, w := range result.Data {
			byName[w.WorkloadName] = w
		}

		clean := byName["a-clean"]
		if clean.Vulns == nil {
			t.Fatal("a matched workload with no findings must report zeros, not nothing")
		}
		is.Equal(*clean.Vulns, service.VulnCounts{})

		if byName["c-unmatched"].Vulns != nil {
			t.Fatal("an unmatched workload must report no counts at all")
		}
	})

	t.Run("vuln_count sorts by severity and puts the unassessed last", func(t *testing.T) {
		is := is.New(t)
		order := func(dir string) []string {
			t.Helper()
			result, err := svc.ListWorkloads(ctx, clusterID, service.WorkloadParams{
				SortBy: "vuln_count", SortDir: dir,
			}, vis)
			if err != nil {
				t.Fatalf("listing workloads: %v", err)
			}
			names := make([]string, len(result.Data))
			for i, w := range result.Data {
				names[i] = w.WorkloadName
			}
			return names
		}
		is.Equal(order("desc"), []string{"b-risky", "a-clean", "c-unmatched"})
		// Ascending flips the two assessed rows but not the unassessed one:
		// "least vulnerable first" is a claim only about images we looked at.
		is.Equal(order("asc"), []string{"a-clean", "b-risky", "c-unmatched"})
	})

	// An unrecognised key must not reach the CASE, where it would silently
	// produce an arbitrary order that reads like a working sort.
	t.Run("an unknown sort key falls back to the default ordering", func(t *testing.T) {
		is := is.New(t)
		result, err := svc.ListWorkloads(ctx, clusterID, service.WorkloadParams{
			SortBy: "'; DROP TABLE cluster_workload; --", SortDir: "desc",
		}, vis)
		if err != nil {
			t.Fatalf("listing workloads: %v", err)
		}
		names := make([]string, len(result.Data))
		for i, w := range result.Data {
			names[i] = w.WorkloadName
		}
		is.Equal(names, []string{"a-clean", "b-risky", "c-unmatched"})
	})

	t.Run("text keys sort in both directions", func(t *testing.T) {
		is := is.New(t)
		result, err := svc.ListWorkloads(ctx, clusterID, service.WorkloadParams{
			SortBy: "workload_name", SortDir: "desc",
		}, vis)
		if err != nil {
			t.Fatalf("listing workloads: %v", err)
		}
		is.Equal(result.Data[0].WorkloadName, "c-unmatched")
		is.Equal(result.Data[2].WorkloadName, "a-clean")
	})
}

// seedClusterRegistry inserts a source/registry pair in nsID with an explicit
// URL, enabled flag and repository patterns, which is what auto-ingest
// resolution actually keys on.
func seedClusterRegistry(t *testing.T, pool *pgxpool.Pool, nsID, name, url string, enabled bool, patterns []string) {
	t.Helper()
	srcID := seedSource(t, pool, nsID, "oci_registry", name)
	// Naming the column overrides its DEFAULT '{}', so a nil slice would be
	// sent as NULL and fail the NOT NULL constraint. "No patterns" is an empty
	// array, which is also what the column means: match every repository.
	if patterns == nil {
		patterns = []string{}
	}
	_, err := pool.Exec(t.Context(), `
		INSERT INTO registry (id, url, type, enabled, repository_patterns)
		VALUES ($1, $2, 'generic', $3, $4)
	`, srcID, url, enabled, patterns)
	if err != nil {
		t.Fatalf("insert registry %q: %v", name, err)
	}
}

// fakeRunningImageSubmitter records what auto-ingest asked it to scan, standing
// in for the registry round-trip so the test stays about resolution.
type fakeRunningImageSubmitter struct {
	calls []string
}

func (f *fakeRunningImageSubmitter) SubmitForRunningImage(_ context.Context, reg service.Registry, repo, dgst, _ string) (int, error) {
	f.calls = append(f.calls, reg.URL+"/"+repo+"@"+dgst)
	return 1, nil
}

// TestClusterIngestUnknown covers the auto-ingest resolver against a real
// database: which running images become scan jobs, and — the part that matters
// for the UI — that each image that does not is filed under the reason naming
// its own remedy rather than a single "skipped" total (ADR-044).
func TestClusterIngestUnknown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)
	svc := service.NewClusterService(pool)

	owner := seedUser(t, pool, 9601, "ingest-owner", "member")
	nsID := seedNamespace(t, pool, "ingest-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "ingest-prod")
	cid := mustUUID(t, clusterID)
	vis := service.VisibilityFilter{UserID: owner}

	seedClusterRegistry(t, pool, nsID, "ghcr", "ghcr.io", true, nil)
	seedClusterRegistry(t, pool, nsID, "quay-off", "quay.io", false, nil)
	seedClusterRegistry(t, pool, nsID, "narrow", "registry.example.com", true, []string{"team/**"})
	// A registry that would serve docker.io, but in someone else's namespace.
	// Using it would pull with credentials this cluster was never granted.
	otherOwner := seedUser(t, pool, 9602, "other-owner", "member")
	otherNS := seedNamespace(t, pool, "other-ns", otherOwner, "public")
	seedClusterRegistry(t, pool, otherNS, "hub", "docker.io", true, nil)

	// An image that is already ingested must not appear in the gap at all.
	knownDigest := digest('a')
	seedArtifactSBOM(t, pool, nsID, "ghcr.io/team/known", knownDigest, "")

	observed := time.Now().UTC()
	upsert := func(name, ref, dgst string) {
		t.Helper()
		var d pgtype.Text
		if dgst != "" {
			d = txt(dgst)
		}
		err := q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID:     cid,
			K8sNamespace:  "prod",
			WorkloadKind:  "Deployment",
			WorkloadName:  name,
			ContainerName: "app",
			ImageRef:      ref,
			ImageDigest:   d,
			PodCount:      1,
			ObservedAt:    pgtype.Timestamptz{Time: observed, Valid: true},
		})
		if err != nil {
			t.Fatalf("upsert %q: %v", name, err)
		}
	}

	upsert("known", "ghcr.io/team/known:v1", knownDigest)
	upsert("api", "ghcr.io/team/api:v1", digest('b'))
	upsert("api-replica", "ghcr.io/team/api:v1", digest('b')) // same image, one remedy
	upsert("legacy", "quay.io/team/legacy:v1", digest('c'))
	upsert("tools", "registry.example.com/other/tools:v1", digest('d'))
	upsert("hub-app", "docker.io/library/nginx:1.27", digest('e'))
	upsert("nameless", "sha256:deadbeef", "") // unresolvable: no digest at all

	sub := &fakeRunningImageSubmitter{}
	res, err := svc.IngestUnknown(ctx, clusterID, sub, service.IngestUnknownParams{}, vis)
	is.NoErr(err)

	// The ingested image and the digest-less workload are both absent from the
	// gap: one has nothing to do, the other has nothing ingest can do.
	is.Equal(res.Considered, 4)
	is.Equal(res.Queued, 1)
	is.Equal(res.SkippedRegistryDisabled, 1) // quay.io is switched off
	is.Equal(res.SkippedPatternExcluded, 1)  // other/** is not team/**
	is.Equal(res.SkippedNoRegistry, 1)       // docker.io registry is another namespace's
	is.Equal(res.Failed, 0)

	is.Equal(len(sub.calls), 1)
	is.Equal(sub.calls[0], "ghcr.io/team/api@"+digest('b'))

	// The listing the Gaps tab renders must agree with what ingest did, since
	// they share a resolver: same four images, same four reasons.
	page, err := svc.UnknownImages(ctx, clusterID, 200, 0, vis)
	is.NoErr(err)
	is.Equal(len(page.Images.Data), 4)
	is.Equal(page.Images.Total, int64(4))
	is.Equal(page.Reasons[service.IngestReasonReady], int64(1))
	is.Equal(page.Reasons[service.IngestReasonRegistryDisabled], int64(1))
	is.Equal(page.Reasons[service.IngestReasonPatternExcluded], int64(1))
	is.Equal(page.Reasons[service.IngestReasonNoRegistry], int64(1))

	// A short page must not shorten the story it tells about the gap. The total
	// and the reason tally describe all four images while only two are
	// returned, which is what stops the Gaps tab from truncating in silence and
	// the Overview from counting the page it happens to hold (ADR-044 K5).
	short, err := svc.UnknownImages(ctx, clusterID, 2, 0, vis)
	is.NoErr(err)
	is.Equal(len(short.Images.Data), 2)
	is.Equal(short.Images.Total, int64(4))
	is.Equal(short.Reasons, page.Reasons)

	// The second page holds the rest, in the same order, with no row repeated
	// or dropped across the seam.
	rest, err := svc.UnknownImages(ctx, clusterID, 2, 2, vis)
	is.NoErr(err)
	is.Equal(len(rest.Images.Data), 2)
	is.Equal(rest.Images.Data[0].ImageRef, page.Images.Data[2].ImageRef)
	is.Equal(rest.Images.Data[1].ImageRef, page.Images.Data[3].ImageRef)

	// Paging off the end is empty, not an error — and still reports the total,
	// so a client that has overshot can tell that it has.
	past, err := svc.UnknownImages(ctx, clusterID, 2, 400, vis)
	is.NoErr(err)
	is.Equal(len(past.Images.Data), 0)
	is.Equal(past.Images.Total, int64(4))

	// Naming one digest ingests one image: the per-row button in the UI would
	// otherwise queue the whole cluster while claiming to queue a row.
	one := &fakeRunningImageSubmitter{}
	scoped, err := svc.IngestUnknown(ctx, clusterID, one,
		service.IngestUnknownParams{ImageDigests: []string{digest('b')}}, vis)
	is.NoErr(err)
	is.Equal(scoped.Considered, 1)
	is.Equal(scoped.Queued, 1)
	is.Equal(len(one.calls), 1)
}

// TestClusterAutoIngestDefaultsOn pins the default. A cluster that reports what
// it runs and then leaves it unscanned is the gap the inventory exists to
// close, so opt-out is the only defensible direction for the flag.
func TestClusterAutoIngestDefaultsOn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	is := is.New(t)
	svc := service.NewClusterService(pool)

	owner := seedUser(t, pool, 9603, "autoingest-owner", "member")
	nsID := seedNamespace(t, pool, "autoingest-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "autoingest-prod")

	cluster, err := svc.Get(t.Context(), clusterID)
	is.NoErr(err)
	is.True(cluster.AutoIngest)

	// A rename must not switch it off as a side effect: the field is a pointer
	// precisely so an omitted value means "leave it alone".
	renamed, err := svc.Update(t.Context(), service.UpdateClusterParams{ID: clusterID, Name: "renamed"})
	is.NoErr(err)
	is.True(renamed.AutoIngest)

	off := false
	updated, err := svc.Update(t.Context(), service.UpdateClusterParams{
		ID: clusterID, Name: "renamed", AutoIngest: &off,
	})
	is.NoErr(err)
	is.True(!updated.AutoIngest)
}

// TestClusterImagesGrouping is the by-image view of the same inventory the
// by-workload list reports.
//
// The two must agree about every image: a reader who switches grouping and sees
// an image go from unknown to matched has no way to tell which view is lying,
// and the by-image row is the one that decides whether an SBOM gets ingested.
// The match expression is copied between the two queries, so this test is what
// keeps the copies honest.
func TestClusterImagesGrouping(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	owner := seedUser(t, pool, 9401, "images-owner", "member")
	nsID := seedNamespace(t, pool, "images-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "prod")

	sharedDigest := digest('a')
	loneDigest := digest('b')
	seedArtifactSBOM(t, pool, nsID, "docker.io/shared", sharedDigest, "")

	observed := time.Now().UTC()
	upsert := func(k8sNS, workload, ref, dgst string, pods int32) {
		t.Helper()
		var d pgtype.Text
		if dgst != "" {
			d = txt(dgst)
		}
		err := q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID:     mustUUID(t, clusterID),
			K8sNamespace:  k8sNS,
			WorkloadKind:  "Deployment",
			WorkloadName:  workload,
			ContainerName: "app",
			ImageRef:      ref,
			ImageDigest:   d,
			PodCount:      pods,
			ObservedAt:    pgtype.Timestamptz{Time: observed, Valid: true},
		})
		if err != nil {
			t.Fatalf("upsert %q: %v", workload, err)
		}
	}

	// One image on two workloads in two namespaces — the case the by-workload
	// view renders as two near-identical rows and one SBOM fixes.
	upsert("default", "web", "docker.io/shared:v1", sharedDigest, 3)
	upsert("batch", "worker", "docker.io/shared:v1", sharedDigest, 2)
	upsert("default", "lone", "docker.io/lone:v1", loneDigest, 1)
	upsert("default", "no-digest", "docker.io/mystery:v1", "", 4)

	images, err := q.ListClusterImages(ctx, repository.ListClusterImagesParams{
		ClusterID: mustUUID(t, clusterID),
		UserID:    owner,
		IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("listing images: %v", err)
	}
	// Four workload-containers, three distinct images.
	is.Equal(len(images), 3)

	byRef := map[string]repository.ListClusterImagesRow{}
	for _, r := range images {
		byRef[r.ImageRef] = r
	}

	shared := byRef["docker.io/shared:v1"]
	is.Equal(shared.WorkloadCount, int64(2))
	is.Equal(shared.PodCount, int64(5))
	is.Equal(shared.NamespaceCount, int64(2))
	is.Equal(shared.MatchState, "exact")

	is.Equal(byRef["docker.io/lone:v1"].WorkloadCount, int64(1))
	is.Equal(byRef["docker.io/lone:v1"].MatchState, "unknown")
	// A NULL digest still groups: an unresolvable image is a row, not a silent
	// omission (ADR-044 K5).
	is.Equal(byRef["docker.io/mystery:v1"].MatchState, "unresolvable")
	is.Equal(byRef["docker.io/mystery:v1"].PodCount, int64(4))

	total, err := q.CountClusterImages(ctx, repository.CountClusterImagesParams{
		ClusterID: mustUUID(t, clusterID),
		UserID:    owner,
		IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("counting images: %v", err)
	}
	// Distinct images, not the workload-containers running them.
	is.Equal(total, int64(3))

	// Parity with the by-workload list, which is the point: same digest, same
	// verdict.
	workloads, err := q.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
		ClusterID: mustUUID(t, clusterID),
		UserID:    owner,
		IsAdmin:   pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("listing workloads: %v", err)
	}
	for _, w := range workloads {
		img, ok := byRef[w.ClusterWorkload.ImageRef]
		is.True(ok) // every running image appears in the by-image list
		is.Equal(img.MatchState, w.MatchState)
		is.Equal(img.SbomID, w.SbomID)
	}

	// The namespace filter applies before the grouping, so filtering to one
	// namespace counts that namespace's replicas rather than the cluster's.
	inDefault, err := q.ListClusterImages(ctx, repository.ListClusterImagesParams{
		ClusterID:    mustUUID(t, clusterID),
		K8sNamespace: txt("default"),
		UserID:       owner,
		IsAdmin:      pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("listing images in one namespace: %v", err)
	}
	for _, r := range inDefault {
		if r.ImageRef == "docker.io/shared:v1" {
			is.Equal(r.WorkloadCount, int64(1))
			is.Equal(r.PodCount, int64(3))
			is.Equal(r.NamespaceCount, int64(1))
		}
	}

	// match_state applies after grouping, because it is a property of the image.
	gaps, err := q.ListClusterImages(ctx, repository.ListClusterImagesParams{
		ClusterID:  mustUUID(t, clusterID),
		MatchState: txt("unknown"),
		UserID:     owner,
		IsAdmin:    pgtype.Bool{Bool: false, Valid: true},
	})
	if err != nil {
		t.Fatalf("listing unknown images: %v", err)
	}
	is.Equal(len(gaps), 1)
	is.Equal(gaps[0].ImageRef, "docker.io/lone:v1")
}
