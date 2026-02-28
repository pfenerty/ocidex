// Package main is the entry point for the OCIDex enrichment worker.
// It consumes SBOMIngested events from NATS JetStream, runs the enrichment
// pipeline, and persists results. Designed to run as a standalone process
// alongside the main ocidex server when ENRICHMENT_NATS_MODE=true.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/enrichment/oci"
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
	)

	ctx := context.Background()
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("parsing database config: %w", err)
	}
	if cfg.DatabaseMaxConns > 0 {
		poolCfg.MaxConns = int32(cfg.DatabaseMaxConns)
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
	insecureResolver := func(host string) bool {
		regs, err := registrySvc.List(context.Background())
		if err != nil {
			return false
		}
		for _, r := range regs {
			regHost := r.URL
			if i := strings.Index(regHost, "://"); i != -1 {
				regHost = regHost[i+3:]
			}
			regHost = strings.TrimSuffix(regHost, "/")
			if regHost == host && r.Insecure {
				return true
			}
		}
		return false
	}

	enrichStore := repository.New(pool)
	ociEnricher := oci.NewEnricher(oci.WithInsecureResolver(insecureResolver))
	dispatcher := enrichment.NewDispatcher(
		enrichStore,
		[]enrichment.Enricher{ociEnricher},
		enrichment.WithWorkers(cfg.EnrichmentWorkers),
		enrichment.WithQueueSize(cfg.EnrichmentQueueSize),
	)
	reg.Register(enrichment.NewNATSExtension(natsClient, dispatcher, logger))

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
