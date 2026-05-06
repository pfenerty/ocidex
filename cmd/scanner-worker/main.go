// Package main is the entry point for the OCIDex scanner worker.
// It consumes scan requests from NATS JetStream, runs Syft, and ingests
// the resulting SBOMs. Requires OCIDEX_MODE=distributed.
//
// Pass --once to scan a single image and exit (K8s Job mode). Set SCAN_IMAGE
// and optionally SCAN_REGISTRY_ID, SCAN_INSECURE, SCAN_AUTH_USERNAME, SCAN_AUTH_TOKEN.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
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
	once := flag.Bool("once", false, "Scan a single image and exit (K8s Job mode)")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if !cfg.IsDistributed() {
		return fmt.Errorf("scanner-worker requires OCIDEX_MODE=distributed")
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.SlogLevel(),
	})))
	slog.Info("starting scanner-worker",
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
		return runOnce(ctx, pool)
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
	registry := extension.NewRegistry(bus, logger)

	// Relay SBOM events to NATS so enrichment workers can pick them up.
	registry.Register(natspkg.NewRelayExtension(natsClient, cfg.NATSStreamName, logger))

	// Wire scanner worker: stateless scanner + nil OCI validator (webhook confirms image exists).
	jobSvc := service.NewJobService(pool)
	scannerSbomSvc := service.NewSBOMService(pool, bus, nil)
	sc := scanner.NewSyftScanner(logger)
	dispatcher := scanner.NewDispatcher(sc, scannerSbomSvc, cfg.ScannerWorkers, cfg.ScannerQueueSize, logger, jobSvc)
	// scanMsgTimeout is set just under the consumer AckWait (10m) so a hung goroutine
	// is cancelled and the semaphore slot released before JetStream redelivers.
	const scanMsgTimeout = 9 * time.Minute
	registry.Register(scanner.NewNATSExtension(natsClient, dispatcher, cfg.NATSStreamName, logger, jobSvc, scanMsgTimeout))

	if err := registry.InitAll(); err != nil {
		return fmt.Errorf("initializing extensions: %w", err)
	}

	extCtx, extCancel := context.WithCancel(context.Background())
	defer extCancel()

	if err := registry.StartAll(extCtx); err != nil {
		return fmt.Errorf("starting extensions: %w", err)
	}

	// Sweep jobs stuck in 'running' at startup, then every 5 minutes.
	// Covers the case where a prior worker crashed before completing a job.
	const jobTimeout = 30 * time.Minute
	if err := jobSvc.TimeoutJobs(ctx, jobTimeout); err != nil {
		slog.Warn("startup timeout sweep failed", "err", err)
	}
	reaperCtx, reaperCancel := context.WithCancel(context.Background())
	defer reaperCancel()
	go runJobReaper(reaperCtx, jobSvc, jobTimeout)

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

// runOnce scans a single image (from env vars) and ingests the resulting SBOM.
// Env vars: SCAN_IMAGE (required), SCAN_REGISTRY_ID, SCAN_INSECURE, SCAN_AUTH_USERNAME, SCAN_AUTH_TOKEN.
func runOnce(ctx context.Context, pool *pgxpool.Pool) error {
	imageRef := os.Getenv("SCAN_IMAGE")
	if imageRef == "" {
		return fmt.Errorf("SCAN_IMAGE is required in --once mode")
	}
	registryIDStr := os.Getenv("SCAN_REGISTRY_ID")
	insecure := os.Getenv("SCAN_INSECURE") == "true"
	authUser := os.Getenv("SCAN_AUTH_USERNAME")
	authToken := os.Getenv("SCAN_AUTH_TOKEN")

	registryURL, repo, digest, tag, err := parseImageRef(imageRef)
	if err != nil {
		return fmt.Errorf("parsing SCAN_IMAGE: %w", err)
	}

	start := time.Now()
	slog.Info("scan started", "image", imageRef, "repo", repo, "digest", digest, "tag", tag) //nolint:gosec // G706: imageRef is a trusted env var

	logger := slog.Default()
	bus := event.NewBus(logger)
	sbomSvc := service.NewSBOMService(pool, bus, nil)
	sc := scanner.NewSyftScanner(logger)

	req := scanner.ScanRequest{
		RegistryURL:  registryURL,
		Repository:   repo,
		Digest:       digest,
		Tag:          tag,
		Insecure:     insecure,
		AuthUsername: authUser,
		AuthToken:    authToken,
		RegistryID:   registryIDStr,
	}

	raw, err := sc.Scan(ctx, req)
	if err != nil {
		return fmt.Errorf("scanning image: %w", err)
	}
	slog.Info("scan complete", "image", imageRef, "duration_ms", time.Since(start).Milliseconds()) //nolint:gosec // G706: imageRef is a trusted env var

	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		return fmt.Errorf("decoding SBOM: %w", err)
	}

	var registryID pgtype.UUID
	if registryIDStr != "" {
		_ = registryID.Scan(registryIDStr)
	}

	if _, err := sbomSvc.Ingest(ctx, bom, raw, service.IngestParams{
		Version:    tag,
		RegistryID: registryID,
	}); err != nil {
		return fmt.Errorf("ingesting SBOM: %w", err)
	}

	slog.Info("ingest complete", "image", imageRef, "total_duration_ms", time.Since(start).Milliseconds()) //nolint:gosec // G706: imageRef is a trusted env var
	return nil
}

// parseImageRef parses an OCI image reference into its components.
// Accepts "registry/repo@digest" or "registry/repo:tag@digest".
func parseImageRef(ref string) (registryURL, repo, digest, tag string, err error) {
	atIdx := strings.LastIndex(ref, "@")
	if atIdx < 0 {
		return "", "", "", "", fmt.Errorf("missing digest separator (@) in %q", ref)
	}
	digest = ref[atIdx+1:]
	nameTag := ref[:atIdx]

	slashIdx := strings.Index(nameTag, "/")
	if slashIdx < 0 {
		return "", "", "", "", fmt.Errorf("missing repository path in %q", ref)
	}
	registryURL = nameTag[:slashIdx]
	repoTag := nameTag[slashIdx+1:]

	colonIdx := strings.LastIndex(repoTag, ":")
	if colonIdx >= 0 {
		repo = repoTag[:colonIdx]
		tag = repoTag[colonIdx+1:]
	} else {
		repo = repoTag
	}

	return registryURL, repo, digest, tag, nil
}

func runJobReaper(ctx context.Context, jobSvc service.JobService, timeout time.Duration) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := jobSvc.TimeoutJobs(ctx, timeout); err != nil && ctx.Err() == nil {
				slog.Warn("timeout sweep failed", "err", err)
			}
		case <-ctx.Done():
			return
		}
	}
}
