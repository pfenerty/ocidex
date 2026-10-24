package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/service"
)

// queueingSubmitter stands in for the scanner's ClusterIngestor: it enqueues a
// real scan job under the key NATSSubmitter would use, and refuses any host in
// refuse. calls records every host contact, which is what a repeat snapshot
// must not make.
type queueingSubmitter struct {
	jobs   service.JobService
	refuse map[string]string // host -> refusal reason
	calls  []string
}

func (f *queueingSubmitter) SubmitForRunningImage(ctx context.Context, target service.RunningImageTarget, repo, dgst, tag string) (int, error) {
	f.calls = append(f.calls, target.Host+"/"+repo+"@"+dgst)
	if reason, ok := f.refuse[target.Host]; ok {
		return 0, &service.IngestRefusedError{Reason: reason, Err: errors.New("manifest HEAD returned HTTP 401")}
	}
	p := service.EnqueueParams{ClusterID: target.ClusterID, Repository: repo, Digest: dgst, Tag: tag}
	attribution := target.ClusterID
	if target.Registry != nil {
		p.RegistryID = target.Registry.ID
		if attribution == "" {
			attribution = target.Registry.ID
		}
	} else {
		p.RegistryHost = target.Host
	}
	p.MsgID = service.ScanJobKey(attribution, dgst)
	if _, err := f.jobs.EnqueueJob(ctx, p); err != nil {
		return 0, err
	}
	return 1, nil
}

// TestClusterCoverageAnonymous covers ADR-0044 K10 for hosts no registry
// serves: the image is queued anonymously and attributed to the cluster's own
// source, a refused host is recorded once and never asked again by a repeat
// snapshot, an explicit Ingest of the row asks again, and a pruned job stays
// pruned.
func TestClusterCoverageAnonymous(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	is := is.New(t)
	q := repository.New(pool)
	svc := service.NewClusterService(pool, nil)
	jobs := service.NewJobService(pool, nil)

	owner := seedUser(t, pool, 9701, "coverage-owner", "member")
	nsID := seedNamespace(t, pool, "coverage-ns", owner, "private")
	clusterID := seedCluster(t, pool, nsID, "coverage-prod")
	cid := mustUUID(t, clusterID)
	vis := service.VisibilityFilter{UserID: owner}

	// Every cluster has a source of its own, in its namespace (migration 00088).
	var srcNS, srcKind string
	is.NoErr(pool.QueryRow(ctx, `SELECT namespace_id::text, kind FROM source WHERE id = $1`, cid).Scan(&srcNS, &srcKind))
	is.Equal(srcNS, nsID)
	is.Equal(srcKind, "cluster")

	observed := pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	for _, w := range []struct{ name, ref, dgst string }{
		{"static", "cgr.dev/chainguard/static:latest", digest('1')},
		{"private", "private.example.com/team/app:v1", digest('2')},
		{"gone", "cgr.dev/chainguard/busybox:latest", digest('3')},
	} {
		is.NoErr(q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID: cid, K8sNamespace: "prod", WorkloadKind: "Deployment", WorkloadName: w.name,
			ContainerName: "app", ImageRef: w.ref, ImageDigest: txt(w.dgst), PodCount: 1, ObservedAt: observed,
		}))
	}
	// An SBOM of busybox was deleted on purpose: its job is a tombstone.
	_, err := pool.Exec(ctx, `
		INSERT INTO scan_jobs (cluster_id, registry_host, repository, digest, nats_msg_id, state)
		VALUES ($1, 'cgr.dev', 'chainguard/busybox', $2, $3, 'pruned')`,
		cid, digest('3'), service.ScanJobKey(clusterID, digest('3')))
	is.NoErr(err)

	sub := &queueingSubmitter{jobs: jobs, refuse: map[string]string{"private.example.com": service.IngestReasonUnauthorized}}
	res, err := svc.IngestUnknown(ctx, clusterID, sub, service.IngestUnknownParams{}, vis)
	is.NoErr(err)
	is.Equal(res.Considered, 3)
	is.Equal(res.Queued, 1)
	is.Equal(res.Unauthorized, 1)
	is.Equal(res.SkippedExisting, 1) // the tombstone
	is.Equal(len(sub.calls), 2)

	// The anonymous job is the cluster's: no registry, the host to pull from,
	// and a claim that pulls it over HTTPS and attributes it to the cluster.
	claim, ok, err := jobs.ClaimNext(ctx, "w-1")
	is.NoErr(err)
	is.True(ok)
	is.Equal(claim.RegistryID, "")
	is.Equal(claim.ClusterID, clusterID)
	is.Equal(claim.RegistryURL, "https://cgr.dev")
	is.Equal(claim.Digest, digest('1'))

	// The refusal is a failed job carrying its reason.
	var lastError string
	is.NoErr(pool.QueryRow(ctx, `SELECT last_error FROM scan_jobs WHERE nats_msg_id = $1 AND state = 'failed'`,
		service.ScanJobKey(clusterID, digest('2'))).Scan(&lastError))
	is.Equal(lastError, "unauthorized: manifest HEAD returned HTTP 401")

	// A repeat snapshot contacts no host.
	sub.calls = nil
	res, err = svc.IngestUnknown(ctx, clusterID, sub, service.IngestUnknownParams{}, vis)
	is.NoErr(err)
	is.Equal(len(sub.calls), 0)
	is.Equal(res.Queued, 0)
	is.Equal(res.Unauthorized, 1)
	is.Equal(res.SkippedExisting, 2)

	page, err := svc.UnknownImages(ctx, clusterID, 50, 0, vis)
	is.NoErr(err)
	is.Equal(page.Reasons[service.IngestReasonScanning], int64(1))
	is.Equal(page.Reasons[service.IngestReasonUnauthorized], int64(1))
	is.Equal(page.Reasons[service.IngestReasonDeleted], int64(1))
	// The refused host is the registry to add.
	is.Equal(len(page.Hosts), 1)
	is.Equal(page.Hosts[0].Host, "private.example.com")
	is.Equal(page.Hosts[0].Reason, service.IngestReasonUnauthorized)

	// Naming the refused row is its retry: the host is asked again and the
	// new outcome replaces the old record. Naming the pruned row is not.
	sub.calls = nil
	res, err = svc.IngestUnknown(ctx, clusterID, sub,
		service.IngestUnknownParams{ImageDigests: []string{digest('2'), digest('3')}}, vis)
	is.NoErr(err)
	is.Equal(sub.calls, []string{"private.example.com/team/app@" + digest('2')})
	is.Equal(res.Unauthorized, 1)
	is.Equal(res.SkippedExisting, 1)
	var failed int
	is.NoErr(pool.QueryRow(ctx, `SELECT count(*) FROM scan_jobs WHERE digest = $1`, digest('2')).Scan(&failed))
	is.Equal(failed, 1)

	// The cluster's source follows its name and goes with it.
	_, err = pool.Exec(ctx, `UPDATE cluster SET name = 'coverage-renamed' WHERE id = $1`, cid)
	is.NoErr(err)
	var srcName string
	is.NoErr(pool.QueryRow(ctx, `SELECT name FROM source WHERE id = $1`, cid).Scan(&srcName))
	is.Equal(srcName, "cluster:coverage-renamed")
	_, err = pool.Exec(ctx, `DELETE FROM cluster WHERE id = $1`, cid)
	is.NoErr(err)
	var sources int
	is.NoErr(pool.QueryRow(ctx, `SELECT count(*) FROM source WHERE id = $1`, cid).Scan(&sources))
	is.Equal(sources, 0)
}
