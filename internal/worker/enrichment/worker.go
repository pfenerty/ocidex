// Package enrichmentworker provides the shared daemon scaffolding used by
// all per-enricher worker binaries.
//
// Pass --once to enrich a single SBOM and exit (K8s Job mode).
// Set ENRICH_SBOM_ID to the UUID of the SBOM to enrich in that mode.
package enrichmentworker

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/extension"
	"github.com/pfenerty/ocidex/internal/health"
	"github.com/pfenerty/ocidex/internal/jobqueue"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/service"
)

// RunConfig scopes a worker to a specific enricher queue partition.
type RunConfig struct {
	// EnricherName is passed to NewEnrichJobService to scope ClaimNext.
	// Use "all" for the legacy all-enrichers model.
	EnricherName string
	// HintDurable is the JetStream durable consumer name. Must be unique per
	// worker type. Convention: "enrich-hint-" + enricher_name.
	HintDurable string
}

// EnricherFactory is called with the live DB pool so resolver-dependent
// enrichers (oci, provenance) can be constructed without the caller needing
// to set up the pool before invoking Run.
type EnricherFactory func(pool *pgxpool.Pool) []enrichment.Enricher

// Run is the shared daemon entry point for all per-enricher workers.
// It handles config load, logging, DB pool, NATS, jobqueue.Worker,
// health server (:9090), and graceful shutdown.
func Run(factory EnricherFactory, cfg RunConfig) error {
	once := flag.Bool("once", false, "Enrich a single SBOM and exit (K8s Job mode)")
	flag.Parse()

	appCfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: appCfg.SlogLevel(),
	})))
	slog.Info("starting enrichment-worker",
		"environment", appCfg.Environment,
		"log_level", appCfg.LogLevel,
		"enricher", cfg.EnricherName,
		"once", *once,
	)

	ctx := context.Background()
	poolCfg, err := pgxpool.ParseConfig(appCfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("parsing database config: %w", err)
	}
	if appCfg.DatabaseMaxConns > 0 {
		poolCfg.MaxConns = int32(appCfg.DatabaseMaxConns) //nolint:gosec // G115: value is a configured pool size
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}
	slog.Info("database connected")

	if *once {
		return RunOnce(ctx, pool, factory)
	}

	natsClient, err := natspkg.Connect(natspkg.Config{
		URL:           appCfg.NATSURL,
		StreamName:    appCfg.NATSStreamName,
		EventTTLHours: appCfg.NATSEventTTL,
		Replicas:      appCfg.NATSStreamReplicas,
	})
	if err != nil {
		return fmt.Errorf("connecting to NATS: %w", err)
	}
	defer natsClient.Close()
	slog.Info("NATS connected", "url", appCfg.NATSURL, "stream", appCfg.NATSStreamName)

	logger := slog.Default()
	bus := event.NewBus(logger)
	reg := extension.NewManager(bus, logger)

	enrichStore := repository.New(pool)
	enrichReg := enrichment.NewCatalog()
	for _, e := range factory(pool) {
		enrichReg.Register(e)
	}
	dispatcher := enrichment.NewDispatcher(enrichStore, enrichReg)

	enrichJobSvc := service.NewEnrichJobService(pool, cfg.EnricherName)
	workerID, _ := os.Hostname()
	enrichProcessor := func(ctx context.Context, claim service.EnrichJobClaim) error {
		ref := enrichment.SubjectRef{
			SBOMId:         claim.SBOMId,
			ArtifactType:   claim.ArtifactType,
			ArtifactName:   claim.ArtifactName,
			Digest:         claim.Digest,
			IndexDigest:    claim.IndexDigest,
			SubjectVersion: claim.SubjectVersion,
			Architecture:   claim.Architecture,
			BuildDate:      claim.BuildDate,
		}
		if err := dispatcher.ProcessOne(ctx, ref); err != nil {
			return err
		}
		if err := enrichJobSvc.FinishByID(ctx, claim.ID); err != nil {
			return err
		}
		enqueueDependents(ctx, enrichStore, enrichJobSvc, natsClient.JS, appCfg.NATSStreamName,
			claim.SBOMId, claim.Architecture, claim.BuildDate, cfg.EnricherName, logger)
		return nil
	}
	reg.Register(jobqueue.NewWorker(
		cfg.HintDurable,
		natsClient,
		appCfg.NATSStreamName,
		enrichJobSvc,
		enrichProcessor,
		jobqueue.Config{
			WorkerID:          workerID,
			MaxConc:           appCfg.EnrichmentMaxConcurrency,
			PollInterval:      appCfg.EnrichmentPollInterval,
			JobTimeout:        appCfg.EnrichmentStuckThreshold,
			MaxAttempts:       int32(appCfg.EnrichmentMaxAttempts), //nolint:gosec // G115: small bounded retry count
			StuckThreshold:    appCfg.EnrichmentStuckThreshold,
			HintSubjectSuffix: ".enrich.hint",
			HintDurable:       cfg.HintDurable,
		},
		logger,
	))

	if err := reg.InitAll(); err != nil {
		return fmt.Errorf("initializing extensions: %w", err)
	}

	extCtx, extCancel := context.WithCancel(context.Background())
	defer extCancel()

	if err := reg.StartAll(extCtx); err != nil {
		return fmt.Errorf("starting extensions: %w", err)
	}

	healthSrv := health.New(":9090", pool, natsClient, slog.Default())
	healthSrv.Start()
	defer healthSrv.Stop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("shutdown signal received", "signal", sig)

	extCancel()
	if err := reg.StopAll(); err != nil {
		slog.Error("extension shutdown error", "err", err)
	}

	slog.Info("enrichment-worker stopped")
	return nil
}

// RunOnce enriches a single SBOM (from ENRICH_SBOM_ID env var) and exits.
// Called from Run when --once is set; also exported for testing.
func RunOnce(ctx context.Context, pool *pgxpool.Pool, factory EnricherFactory) error {
	sbomIDStr := os.Getenv("ENRICH_SBOM_ID")
	if sbomIDStr == "" {
		return fmt.Errorf("ENRICH_SBOM_ID is required in --once mode")
	}

	start := time.Now()
	slog.Info("enrichment started", "sbom_id", sbomIDStr) //nolint:gosec // G706: sbomIDStr is a trusted env var

	var sbomID pgtype.UUID
	if err := sbomID.Scan(sbomIDStr); err != nil {
		return fmt.Errorf("parsing ENRICH_SBOM_ID %q: %w", sbomIDStr, err)
	}

	store := repository.New(pool)

	sbomRow, err := store.GetSBOM(ctx, sbomID)
	if err != nil {
		return fmt.Errorf("getting SBOM %s: %w", sbomIDStr, err)
	}

	artifact, err := store.GetArtifact(ctx, sbomRow.ArtifactID)
	if err != nil {
		return fmt.Errorf("getting artifact for SBOM %s: %w", sbomIDStr, err)
	}

	slog.Info("enriching SBOM", "sbom_id", sbomIDStr, "artifact_name", artifact.Name) //nolint:gosec // G706: sbomIDStr is a trusted env var

	ref := enrichment.SubjectRef{
		SBOMId:         sbomID,
		ArtifactType:   artifact.Type,
		ArtifactName:   artifact.Name,
		Digest:         sbomRow.Digest.String,
		IndexDigest:    sbomRow.IndexDigest.String,
		SubjectVersion: sbomRow.SubjectVersion.String,
	}

	enrichReg := enrichment.NewCatalog()
	for _, e := range factory(pool) {
		enrichReg.Register(e)
	}
	dispatcher := enrichment.NewDispatcher(store, enrichReg)

	if err := dispatcher.ProcessOne(ctx, ref); err != nil {
		return fmt.Errorf("enriching SBOM: %w", err)
	}

	slog.Info("enrichment complete", "sbom_id", sbomIDStr, "duration_ms", time.Since(start).Milliseconds()) //nolint:gosec // G706: sbomIDStr is a trusted env var
	return nil
}
