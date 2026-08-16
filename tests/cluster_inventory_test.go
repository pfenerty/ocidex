package tests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
	"github.com/pressly/goose/v3"

	"github.com/pfenerty/ocidex/db"
	"github.com/pfenerty/ocidex/internal/repository"
)

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

	if err := goose.Down(sqlDB, "migrations"); err != nil {
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
