package tests

import (
	"context"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

// recordingSubmitter enqueues like NATSSubmitter without the NATS hint, which
// is best-effort; these tests read the scan_jobs row.
type recordingSubmitter struct {
	jobSvc service.JobService
	states []service.ScanJobState
}

func (r *recordingSubmitter) Submit(ctx context.Context, req scanner.ScanRequest) error {
	job, err := r.jobSvc.Enqueue(ctx, req.RegistryID, req.Repository, req.Digest, req.IndexDigest, req.Tag,
		req.RegistryID+"@"+req.Digest, req.Force)
	if err != nil {
		return err
	}
	r.states = append(r.states, job.State)
	return nil
}

const prunedTestDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func scanJobState(t *testing.T, pool *pgxpool.Pool, registryID string) string {
	t.Helper()
	var state string
	if err := pool.QueryRow(t.Context(),
		`SELECT state FROM scan_jobs WHERE nats_msg_id = $1`, registryID+"@"+prunedTestDigest).Scan(&state); err != nil {
		t.Fatalf("reading scan job: %v", err)
	}
	return state
}

// TestExplicitDeleteLeavesPrunedTombstone covers ocidex-5y0r.5 (ADR-0053 S6):
// deleting a registry-sourced SBOM through the service tombstones its scan job,
// a plain re-submit of the digest leaves the tombstone alone, and a forced one
// re-queues it. DeleteArtifact tombstones every SBOM it removes.
func TestExplicitDeleteLeavesPrunedTombstone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	is := is.New(t)
	ctx := t.Context()
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	regSvc := service.NewRegistryService(pool, nil)
	sbomSvc := service.NewSBOMService(pool, nil, nil)
	jobSvc := service.NewJobService(pool, nil)
	reg, err := regSvc.Create(ctx, service.CreateRegistryParams{
		Name: "pruned-test", Type: "generic", URL: "registry.example", ScanMode: "poll", PollIntervalMinutes: 60,
	})
	is.NoErr(err)
	var sourceID pgtype.UUID
	is.NoErr(sourceID.Scan(reg.ID))

	const digest = prunedTestDigest
	sub := &recordingSubmitter{jobSvc: jobSvc}
	req := scanner.ScanRequest{RegistryID: reg.ID, Repository: "pfenerty/ocidex-api", Digest: digest, Tag: "v0.9.0"}

	// Scan and ingest, as the worker would.
	is.NoErr(sub.Submit(ctx, req))
	_, err = pool.Exec(ctx, `UPDATE scan_jobs SET state = 'succeeded' WHERE nats_msg_id = $1`, reg.ID+"@"+digest)
	is.NoErr(err)
	var bom cdx.BOM
	is.NoErr(json.Unmarshal([]byte(relImageSBOM), &bom))
	sbomID, err := sbomSvc.Ingest(ctx, &bom, []byte(relImageSBOM), service.IngestParams{SourceID: sourceID, Digest: digest})
	is.NoErr(err)

	is.NoErr(sbomSvc.DeleteSBOM(ctx, sbomID))
	is.Equal(scanJobState(t, pool, reg.ID), "pruned")

	// The next walk no longer knows the digest, so it submits it again.
	is.NoErr(sub.Submit(ctx, req))
	is.Equal(scanJobState(t, pool, reg.ID), "pruned")
	is.Equal(sub.states[len(sub.states)-1], service.ScanJobPruned)

	// A forced walk brings it back.
	is.NoErr(scanner.ForceSubmitter{Submitter: sub}.Submit(ctx, req))
	is.Equal(scanJobState(t, pool, reg.ID), "queued")

	t.Run("artifact delete", func(t *testing.T) {
		is := is.New(t)
		_, err := pool.Exec(ctx, `UPDATE scan_jobs SET state = 'succeeded' WHERE nats_msg_id = $1`, reg.ID+"@"+digest)
		is.NoErr(err)
		sbomID, err := sbomSvc.Ingest(ctx, &bom, []byte(relImageSBOM), service.IngestParams{SourceID: sourceID, Digest: digest})
		is.NoErr(err)
		var artifactID pgtype.UUID
		is.NoErr(pool.QueryRow(ctx, `SELECT artifact_id FROM sbom WHERE id = $1`, sbomID).Scan(&artifactID))

		is.NoErr(sbomSvc.DeleteArtifact(ctx, artifactID))
		is.Equal(scanJobState(t, pool, reg.ID), "pruned")
	})
}
