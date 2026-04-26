// Package main is the entry point for the OCIDex enrichment worker.
// It consumes SBOMIngested events from NATS JetStream, runs the enrichment
// pipeline, and persists results. Designed to run as a standalone process
// alongside the main ocidex server when ENRICHMENT_NATS_MODE=true.
//
// Pass --once to enrich a single SBOM and exit (K8s Job mode). Set ENRICH_SBOM_ID
// to the UUID of the SBOM to enrich.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/enrichment/oci"
	"github.com/pfenerty/ocidex/internal/enrichment/user"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/extension"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/service"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	once := flag.Bool("once", false, "Enrich a single SBOM and exit (K8s Job mode)")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.SlogLevel(),
	})))
	slog.Info("starting enrichment-worker",
		"environment", cfg.Environment,
		"log_level", cfg.LogLevel,
		"once", *once,
	)

	ctx := context.Background()
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("parsing database config: %w", err)
	}
	if cfg.DatabaseMaxConns > 0 {
		poolCfg.MaxConns = int32(cfg.DatabaseMaxConns) //nolint:gosec // G115: value is a configured pool size
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
		return runEnrichOnce(ctx, pool)
	}

	natsClient, err := natspkg.Connect(natspkg.Config{
		URL:           cfg.NATSURL,
		StreamName:    cfg.NATSStreamName,
		EventTTLHours: cfg.NATSEventTTL,
		Replicas:      cfg.NATSStreamReplicas,
	})
	if err != nil {
		return fmt.Errorf("connecting to NATS: %w", err)
	}
	defer natsClient.Close()
	slog.Info("NATS connected", "url", cfg.NATSURL, "stream", cfg.NATSStreamName)

	logger := slog.Default()
	bus := event.NewBus(logger)
	reg := extension.NewRegistry(bus, logger)

	registrySvc := service.NewRegistryService(pool)
	insecureResolver := service.BuildInsecureResolver(registrySvc)

	enrichStore := repository.New(pool)
	enrichReg := enrichment.NewRegistry()
	enrichReg.Register(user.NewEnricher())
	enrichReg.Register(oci.NewEnricher(oci.WithInsecureResolver(insecureResolver)))
	dispatcher := enrichment.NewDispatcher(
		enrichStore,
		enrichReg,
		enrichment.WithWorkers(cfg.EnrichmentWorkers),
		enrichment.WithQueueSize(cfg.EnrichmentQueueSize),
	)
	reg.Register(enrichment.NewNATSExtension(natsClient, dispatcher, cfg.NATSStreamName, logger))

	if err := reg.InitAll(); err != nil {
		return fmt.Errorf("initializing extensions: %w", err)
	}

	extCtx, extCancel := context.WithCancel(context.Background())
	defer extCancel()

	if err := reg.StartAll(extCtx); err != nil {
		return fmt.Errorf("starting extensions: %w", err)
	}

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

// runEnrichOnce enriches a single SBOM (from ENRICH_SBOM_ID env var) and exits.
func runEnrichOnce(ctx context.Context, pool *pgxpool.Pool) error {
	sbomIDStr := os.Getenv("ENRICH_SBOM_ID")
	if sbomIDStr == "" {
		return fmt.Errorf("ENRICH_SBOM_ID is required in --once mode")
	}

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

	ref := enrichment.SubjectRef{
		SBOMId:         sbomID,
		ArtifactType:   artifact.Type,
		ArtifactName:   artifact.Name,
		Digest:         sbomRow.Digest.String,
		SubjectVersion: sbomRow.SubjectVersion.String,
	}

	registrySvc := service.NewRegistryService(pool)
	insecureResolver := service.BuildInsecureResolver(registrySvc)

	enrichReg := enrichment.NewRegistry()
	enrichReg.Register(user.NewEnricher())
	enrichReg.Register(oci.NewEnricher(oci.WithInsecureResolver(insecureResolver)))
	dispatcher := enrichment.NewDispatcher(store, enrichReg)

	if err := dispatcher.ProcessOne(ctx, ref); err != nil {
		return fmt.Errorf("enriching SBOM: %w", err)
	}

	slog.Info("enrichment complete", "sbom_id", sbomIDStr) //nolint:gosec // G706: sbomIDStr is a trusted env var, not arbitrary user input
	return nil
}
