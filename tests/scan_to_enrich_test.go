package tests

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	gcname "github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
	natsc "github.com/testcontainers/testcontainers-go/modules/nats"

	"github.com/pfenerty/ocidex/internal/enrichment"
	ocienricher "github.com/pfenerty/ocidex/internal/enrichment/oci"
	"github.com/pfenerty/ocidex/internal/event"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/scanner"
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

// publishScanRequest publishes a scan.requested envelope to JetStream.
func publishScanRequest(t *testing.T, client *natspkg.Client, streamName, digest, architecture, buildDate string) {
	t.Helper()

	type scanRequestWire struct {
		RegistryURL  string `json:"registry_url"`
		Repository   string `json:"repository"`
		Digest       string `json:"digest"`
		Architecture string `json:"architecture,omitempty"`
		BuildDate    string `json:"build_date,omitempty"`
		ImageVersion string `json:"image_version,omitempty"`
	}

	payload, err := json.Marshal(scanRequestWire{
		RegistryURL:  testRegistryURL,
		Repository:   testRepository,
		Digest:       digest,
		Architecture: architecture,
		BuildDate:    buildDate,
		ImageVersion: testImageVersion,
	})
	if err != nil {
		t.Fatalf("marshal scan request: %v", err)
	}

	env := natspkg.Envelope{
		EventType:  "scan.requested",
		OccurredAt: time.Now().UTC(),
		Payload:    json.RawMessage(payload),
	}
	envData, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	pubCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	subject := streamName + ".scan.requested"
	if _, err := client.JS.Publish(pubCtx, subject, envData); err != nil {
		t.Fatalf("publish scan.requested: %v", err)
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
	sc := scanner.NewSyftScanner(logger)
	scanDisp := scanner.NewDispatcher(sc, sbomSvc, 1, 10, logger, nil)

	extCtx, extCancel := context.WithCancel(ctx)
	t.Cleanup(extCancel)

	scanExt := scanner.NewNATSExtension(natsClient, scanDisp, streamName, logger, nil)
	if err := scanExt.Start(extCtx); err != nil {
		t.Fatalf("scanner ext start: %v", err)
	}
	t.Cleanup(func() { _ = scanExt.Stop() })

	// Wire enrichment pipeline: real OCI enricher → real Red Hat registry.
	repoQ := repository.New(pool)
	reg := enrichment.NewRegistry()
	reg.Register(ocienricher.NewEnricher())
	enrichDisp := enrichment.NewDispatcher(repoQ, reg)
	enrichExt := enrichment.NewNATSExtension(natsClient, enrichDisp, streamName, logger)
	if err := enrichExt.Start(extCtx); err != nil {
		t.Fatalf("enrichment ext start: %v", err)
	}
	t.Cleanup(func() { _ = enrichExt.Stop() })

	// Trigger the pipeline by publishing a scan request.
	// All three metadata fields are set so dispatcher.process() skips fillMetadata().
	publishScanRequest(t, natsClient, streamName, digest, architecture, buildDate)

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
