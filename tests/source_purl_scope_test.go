package tests

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// TestSourcePurlFindingCountsEverywhere seeds one finding published against a
// component's source package only, and holds every count that reports it to
// the same answer. The SBOM and artifact counts matched on purl ∪ source_purl
// while the cluster, vulnerability-detail and rollup counts matched on purl
// alone, so the same image read as affected on one page and clean on the next.
func TestSourcePurlFindingCountsEverywhere(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)

	const (
		binaryPurl = "pkg:deb/debian/libssl3@3.0.11-1?arch=amd64"
		sourcePurl = "pkg:deb/debian/openssl@3.0.11-1"
		canonical  = "CVE-2026-50001"
	)

	owner := seedUser(t, pool, 9201, "source-purl-owner", "member")
	nsID := seedNamespace(t, pool, "source-purl-ns", owner, "public")
	clusterID := seedCluster(t, pool, nsID, "prod")
	dgst := digest('e')

	var artifactID, sbomID pgtype.UUID
	is.NoErr(pool.QueryRow(ctx,
		`INSERT INTO artifact (type, name) VALUES ('container', 'docker.io/source-purl') RETURNING id`).Scan(&artifactID))
	is.NoErr(pool.QueryRow(ctx, `
		INSERT INTO sbom (spec_version, raw_bom, digest, artifact_id, namespace_id, subject_version)
		VALUES ('1.6', '{}'::jsonb, $1, $2, $3::uuid, '1.0.0') RETURNING id
	`, dgst, artifactID, nsID).Scan(&sbomID))
	_, err := pool.Exec(ctx, `
		INSERT INTO component (sbom_id, type, name, version, purl, source_purl)
		VALUES ($1, 'library', 'libssl3', '3.0.11-1', $2, $3)
	`, sbomID, binaryPurl, sourcePurl)
	is.NoErr(err)
	// The advisory names the source package, never the binary one.
	seedAdvisory(t, pool, "DEBIAN-CVE-2026-50001", canonical, "HIGH", 7.5, sourcePurl)

	is.NoErr(q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
		ClusterID:     mustUUID(t, clusterID),
		K8sNamespace:  "default",
		WorkloadKind:  "Deployment",
		WorkloadName:  "api",
		ContainerName: "app",
		ImageRef:      "docker.io/source-purl:1.0.0",
		ImageDigest:   txt(dgst),
		PodCount:      1,
		ObservedAt:    pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
	}))
	refreshRollups(t, pool)

	admin := pgtype.Bool{Bool: true, Valid: true}
	cid := mustUUID(t, clusterID)

	sbomSummary, err := q.GetSBOMVulnSummary(ctx, sbomID)
	is.NoErr(err)
	is.Equal(len(sbomSummary), 1) // SBOM

	artifactSummary, err := q.GetArtifactVulnSummary(ctx, repository.GetArtifactVulnSummaryParams{ArtifactID: artifactID, IsAdmin: admin})
	is.NoErr(err)
	is.Equal(artifactSummary.High, int64(1)) // artifact

	running, err := q.ListClusterRunningVulns(ctx, repository.ListClusterRunningVulnsParams{
		ClusterID: cid, IsAdmin: admin, SortBy: "severity", SortDir: "desc",
		Limit: pgtype.Int4{Int32: 10, Valid: true}, Offset: pgtype.Int4{Valid: true},
	})
	is.NoErr(err)
	is.Equal(len(running), 1)
	is.Equal(running[0].CanonicalID, canonical) // cluster running vulns

	total, err := q.CountClusterRunningVulns(ctx, repository.CountClusterRunningVulnsParams{ClusterID: cid, IsAdmin: admin})
	is.NoErr(err)
	is.Equal(total, int64(1)) // cluster running vulns total

	workloads, err := q.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
		ClusterID: cid, IsAdmin: admin, SortBy: "name", SortDir: "asc",
		Limit: pgtype.Int4{Int32: 10, Valid: true}, Offset: pgtype.Int4{Valid: true},
	})
	is.NoErr(err)
	is.Equal(len(workloads), 1)
	is.Equal(workloads[0].HighCount, int64(1)) // cluster workload severity

	byVuln, err := q.ListWorkloadsForVulnerability(ctx, repository.ListWorkloadsForVulnerabilityParams{
		CanonicalID: canonical, IsAdmin: admin, Limit: pgtype.Int4{Int32: 10, Valid: true},
	})
	is.NoErr(err)
	is.Equal(len(byVuln), 1) // vuln detail: running workloads

	artifacts, err := q.ListAffectedArtifactsByVuln(ctx, repository.ListAffectedArtifactsByVulnParams{
		CanonicalID: canonical, IsAdmin: admin, RowLimit: pgtype.Int4{Int32: 10, Valid: true}, RowOffset: pgtype.Int4{Valid: true},
	})
	is.NoErr(err)
	is.Equal(len(artifacts), 1)
	is.Equal(artifacts[0].AffectedPurlCount, int64(1)) // vuln detail: artifacts

	components, err := q.ListAffectedComponentsByVuln(ctx, repository.ListAffectedComponentsByVulnParams{CanonicalID: canonical, IsAdmin: admin})
	is.NoErr(err)
	is.Equal(len(components), 1)
	is.Equal(components[0].Name, "libssl3") // vuln detail: components

	namespaces, err := q.CountAffectedNamespacesByVuln(ctx, repository.CountAffectedNamespacesByVulnParams{CanonicalID: canonical, IsAdmin: admin})
	is.NoErr(err)
	is.Equal(namespaces, int64(1)) // vuln detail: namespaces

	top, err := q.ListTopVulnerabilities(ctx, repository.ListTopVulnerabilitiesParams{
		IsAdmin: admin, SortBy: "severity", SortDir: "desc",
		RowLimit: pgtype.Int4{Int32: 10, Valid: true}, RowOffset: pgtype.Int4{Valid: true},
	})
	is.NoErr(err)
	is.Equal(len(top), 1)
	is.Equal(top[0].AffectedSbomCount, int64(1))
	is.Equal(top[0].AffectedPurlCount, int64(1)) // vulnerability list (vuln_rollup)

	discover, err := q.GetDiscoverTopVulnerabilities(ctx, repository.GetDiscoverTopVulnerabilitiesParams{CandidateLimit: 10, RowLimit: 10})
	is.NoErr(err)
	is.Equal(len(discover), 1)
	is.Equal(discover[0].AffectedArtifactCount, int64(1)) // discover
}
