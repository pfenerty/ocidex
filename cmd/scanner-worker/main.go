// Package main is the entry point for the OCIDex scanner worker.
// It consumes scan requests from NATS JetStream, runs Syft, and ingests
// the resulting SBOMs. Designed to run as a standalone process alongside
// the main ocidex server when SCANNER_NATS_MODE=true.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/extension"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/scanner"
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
	slog.Info("starting scanner-worker",
		"environment", cfg.Environment,
		"log_level", cfg.LogLevel,
	)

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
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
	})
	if err != nil {
		return fmt.Errorf("connecting to NATS: %w", err)
	}
	defer natsClient.Close()
	slog.Info("NATS connected", "url", cfg.NATSURL, "stream", cfg.NATSStreamName)

	logger := slog.Default()
	bus := event.NewBus(logger)
	registry := extension.NewRegistry(bus, logger)

	// Relay SBOM events to NATS so enrichment workers can pick them up.
	registry.Register(natspkg.NewRelayExtension(natsClient, logger))

	// Wire scanner worker: stateless scanner + nil OCI validator (webhook confirms image exists).
	scannerSbomSvc := service.NewSBOMService(pool, bus, nil)
	sc := scanner.NewScanner(logger)
	dispatcher := scanner.NewDispatcher(sc, scannerSbomSvc, cfg.ScannerWorkers, cfg.ScannerQueueSize, logger)
	registry.Register(scanner.NewNATSExtension(natsClient, dispatcher, logger))

	if err := registry.InitAll(); err != nil {
		return fmt.Errorf("initializing extensions: %w", err)
	}

	extCtx, extCancel := context.WithCancel(context.Background())
	defer extCancel()

	if err := registry.StartAll(extCtx); err != nil {
		return fmt.Errorf("starting extensions: %w", err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("shutdown signal received", "signal", sig)

	extCancel()
	if err := registry.StopAll(); err != nil {
		slog.Error("extension shutdown error", "err", err)
	}

	slog.Info("scanner-worker stopped")
	return nil
}
