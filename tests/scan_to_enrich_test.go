package tests

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	gcname "github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
	natsc "github.com/testcontainers/testcontainers-go/modules/nats"

	"github.com/pfenerty/ocidex/internal/enrichment"
	ocienricher "github.com/pfenerty/ocidex/internal/enrichment/oci"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/jobqueue"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/scanner/engine"
	"github.com/pfenerty/ocidex/internal/service"
)

const (
	testRegistryURL  = "registry.access.redhat.com"
	testRepository   = "ubi9/ubi-minimal"
	testImageVersion = "latest"
)

// resolveAMD64Digest resolves the linux/amd64 manifest digest for the test image
// and returns it along with the architecture and build date from the image config.
// Skips the test if the registry is unreachable.
func resolveAMD64Digest(t *testing.T) (digest, architecture, buildDate string) {
	t.Helper()

	imageRef := testRegistryURL + "/" + testRepository + ":" + testImageVersion
	ref, err := gcname.ParseReference(imageRef)
	if err != nil {
		t.Fatalf("parse image ref %q: %v", imageRef, err)
	}

	resolveCtx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	desc, err := remote.Get(ref, remote.WithContext(resolveCtx))
	if err != nil {
		t.Skipf("cannot reach %s (network required): %v", testRegistryURL, err)
	}

	var imageDigest gcname.Digest

	if desc.MediaType.IsIndex() {
		// Navigate to the linux/amd64 manifest.
		idx, err := desc.ImageIndex()
		if err != nil {
			t.Fatalf("get image index: %v", err)
		}
		manifest, err := idx.IndexManifest()
		if err != nil {
			t.Fatalf("get index manifest: %v", err)
		}
		found := false
		for _, m := range manifest.Manifests {
			if m.Platform != nil && m.Platform.Architecture == "amd64" && m.Platform.OS == "linux" {
				imageDigest, err = gcname.NewDigest(testRegistryURL + "/" + testRepository + "@" + m.Digest.String())
				if err != nil {
					t.Fatalf("parse digest ref: %v", err)
				}
				found = true
				break
			}
		}
		if !found {
			t.Fatal("no linux/amd64 manifest found in index")
		}
	} else {
		imageDigest, err = gcname.NewDigest(testRegistryURL + "/" + testRepository + "@" + desc.Digest.String())
		if err != nil {
			t.Fatalf("parse digest ref: %v", err)
		}
	}

	img, err := remote.Image(imageDigest, remote.WithContext(resolveCtx))
	if err != nil {
		t.Fatalf("get image: %v", err)
	}
	cfgFile, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("get image config: %v", err)
	}

	digest = imageDigest.DigestStr()
	architecture = cfgFile.Architecture
	if !cfgFile.Created.IsZero() {
		buildDate = cfgFile.Created.Format(time.RFC3339)
	}
	t.Logf("resolved %s/%s: digest=%s arch=%s built=%s", testRegistryURL, testRepository, digest, architecture, buildDate)
	return digest, architecture, buildDate
}

// enqueueScanJob inserts a registry row + uses NATSSubmitter to enqueue a
// scan and publish a hint. This mirrors how the catalog walker / webhook
// enter the pipeline under the outbox model.
func enqueueScanJob(t *testing.T, pool *pgxpool.Pool, submitter *scanner.NATSSubmitter, digest, architecture, buildDate string) {
	t.Helper()

	regID := pgtype.UUID{}
	_ = regID.Scan("11111111-1111-4111-8111-111111111111")
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO registry (id, name, url, type, enabled)
		VALUES ($1, $2, $3, 'generic', true)
		ON CONFLICT (id) DO NOTHING
	`, regID, "redhat-"+digest[7:15], testRegistryURL); err != nil {
		t.Fatalf("insert registry: %v", err)
	}

	regIDStr := "11111111-1111-4111-8111-111111111111"
	if err := submitter.Submit(t.Context(), scanner.ScanRequest{
		RegistryURL:  testRegistryURL,
		Repository:   testRepository,
		Digest:       digest,
		Tag:          testImageVersion,
		Architecture: architecture,
		BuildDate:    buildDate,
		ImageVersion: testImageVersion,
		RegistryID:   regIDStr,
	}); err != nil {
		t.Fatalf("submit scan: %v", err)
	}
}

// TestScanToEnrichFlow exercises the full pipeline:
// scan.requested (NATS) → scanner → SBOM ingest → relay → sbom.ingested (NATS) → enrichment → DB.
func TestScanToEnrichFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	ctx := t.Context()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	streamName := "ocidex"

	// Resolve real image metadata; skips test if registry unreachable.
	digest, architecture, buildDate := resolveAMD64Digest(t)
	if buildDate == "" {
		t.Skip("image has no build date in config; cannot satisfy container SBOM validation")
	}

	// Start Postgres + NATS.
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	natsContainer, err := natsc.Run(ctx, "docker.io/nats:latest")
	if err != nil {
		t.Fatalf("start nats container: %v", err)
	}
	t.Cleanup(func() { _ = natsContainer.Terminate(ctx) })

	natsURL, err := natsContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("nats connection string: %v", err)
	}
	natsClient, err := natspkg.Connect(natspkg.Config{
		URL:           natsURL,
		StreamName:    streamName,
		EventTTLHours: 1,
	})
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	t.Cleanup(natsClient.Close)

	// Wire event bus + NATS relay (in-process → JetStream bridge).
	bus := event.NewBus(logger)
	relay := natspkg.NewRelayExtension(natsClient, streamName, logger)
	if err := relay.Init(bus); err != nil {
		t.Fatalf("relay init: %v", err)
	}
	if err := relay.Start(ctx); err != nil {
		t.Fatalf("relay start: %v", err)
	}

	// Wire scanner pipeline: real Syft Go library → real Red Hat registry.
	sbomSvc := service.NewSBOMService(pool, bus, nil) // nil validator skips OCI manifest check
	sc := engine.NewSyftScanner(logger)
	scanDisp := engine.NewDispatcher(sc, sbomSvc, logger)

	jobSvc := service.NewJobService(pool)
	submitter := scanner.NewNATSSubmitter(natsClient, streamName, jobSvc)

	extCtx, extCancel := context.WithCancel(ctx)
	t.Cleanup(extCancel)

	scanProcessor := func(scanCtx context.Context, claim service.ScanJobClaim) error {
		req := scanner.ScanRequestFromClaim(claim)
		sbomID, err := scanDisp.ProcessOne(scanCtx, req)
		if err != nil {
			return err
		}
		return jobSvc.FinishByID(scanCtx, claim.ID, sbomID)
	}
	scanExt := jobqueue.NewWorker(
		"scanner-hint",
		natsClient, streamName, jobSvc, scanProcessor,
		jobqueue.Config{
			WorkerID:          "test-worker",
			MaxConc:           1,
			PollInterval:      5 * time.Second,
			JobTimeout:        9 * time.Minute,
			MaxAttempts:       3,
			StuckThreshold:    15 * time.Minute,
			HintSubjectSuffix: scanner.ScanHintSubjectSuffix,
			HintDurable:       scanner.ScannerHintDurable,
		},
		logger,
	)
	if err := scanExt.Start(extCtx); err != nil {
		t.Fatalf("scanner ext start: %v", err)
	}
	t.Cleanup(func() { _ = scanExt.Stop() })

	// Wire enrichment pipeline: DB-backed outbox + real OCI enricher.
	repoQ := repository.New(pool)
	enrichReg := enrichment.NewCatalog()
	enrichReg.Register(ocienricher.NewEnricher())
	enrichDisp := enrichment.NewDispatcher(repoQ, enrichReg)

	enrichJobSvc := service.NewEnrichJobService(pool, "all")

	// The submitter enqueues enrichment_jobs rows when SBOMIngested fires.
	enrichSubmitter := enrichment.NewNATSSubmitter(natsClient, streamName, enrichJobSvc, logger)
	if err := enrichSubmitter.Init(bus); err != nil {
		t.Fatalf("enrich submitter init: %v", err)
	}

	enrichProcessor := func(enrichCtx context.Context, claim service.EnrichJobClaim) error {
		ref := enrichment.SubjectRef{
			SBOMId:         claim.SBOMId,
			ArtifactType:   claim.ArtifactType,
			ArtifactName:   claim.ArtifactName,
			Digest:         claim.Digest,
			SubjectVersion: claim.SubjectVersion,
			Architecture:   claim.Architecture,
			BuildDate:      claim.BuildDate,
		}
		if err := enrichDisp.ProcessOne(enrichCtx, ref); err != nil {
			return err
		}
		return enrichJobSvc.FinishByID(enrichCtx, claim.ID)
	}
	enrichExt := jobqueue.NewWorker(
		"enrichment-hint",
		natsClient, streamName, enrichJobSvc, enrichProcessor,
		jobqueue.Config{
			WorkerID:          "test-worker",
			MaxConc:           1,
			PollInterval:      5 * time.Second,
			JobTimeout:        4 * time.Minute,
			MaxAttempts:       3,
			StuckThreshold:    10 * time.Minute,
			HintSubjectSuffix: ".enrich.hint",
			HintDurable:       "enrichment-hint",
		},
		logger,
	)
	if err := enrichExt.Start(extCtx); err != nil {
		t.Fatalf("enrichment ext start: %v", err)
	}
	t.Cleanup(func() { _ = enrichExt.Stop() })

	// Trigger the pipeline by inserting a scan_jobs row + publishing a hint.
	enqueueScanJob(t, pool, submitter, digest, architecture, buildDate)

	is := is.New(t)

	// Wait for the SBOM to be ingested (Syft downloads image layers — allow up to 4 min).
	var sbomID pgtype.UUID
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		sbomID, _ = repoQ.GetSBOMByDigest(ctx, pgtype.Text{String: digest, Valid: true})
		if sbomID.Valid {
			break
		}
		time.Sleep(5 * time.Second)
	}
	is.True(sbomID.Valid) // SBOM must appear in DB within 4 minutes

	// Wait for the enrichment record to be written.
	var enrichments []repository.ListEnrichmentsBySBOMRow
	for time.Now().Before(deadline) {
		enrichments, _ = repoQ.ListEnrichmentsBySBOM(ctx, sbomID)
		if len(enrichments) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	is.True(len(enrichments) >= 1)
	is.Equal(enrichments[0].EnricherName, "oci-metadata")
	is.Equal(enrichments[0].Status, "success")

	// Assert enrichment_sufficient was set (enrichment_sufficient is not in GetSBOMRow).
	var sufficient bool
	row := pool.QueryRow(ctx, "SELECT enrichment_sufficient FROM sbom WHERE id = $1", sbomID)
	is.NoErr(row.Scan(&sufficient))
	is.True(sufficient)
}
