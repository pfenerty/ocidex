// Package main is the entry point for the OCIDex scanner worker.
// It consumes scan requests from NATS JetStream, runs Syft, and ingests
// the resulting SBOMs.
//
// Pass --once to scan a single image and exit (K8s Job mode). Set SCAN_IMAGE
// and optionally SCAN_REGISTRY_ID, SCAN_INSECURE, SCAN_AUTH_USERNAME, SCAN_AUTH_TOKEN.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/extension"
	"github.com/pfenerty/ocidex/internal/health"
	"github.com/pfenerty/ocidex/internal/jobqueue"
	"github.com/pfenerty/ocidex/internal/metrics"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/scanner/engine"
	"github.com/pfenerty/ocidex/internal/service"
	"github.com/pfenerty/ocidex/internal/tracing"
)

// scanTimeout bounds a single Syft scan. The stuck-running sweep uses a
// slightly larger threshold so a still-active scan is not preempted.
const scanTimeout = 9 * time.Minute

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
	// Before anything clones the default transport: syft's pulls do, per scan.
	engine.GuardDefaultTransport(cfg.EgressPolicy)

	slog.SetDefault(slog.New(tracing.LogHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.SlogLevel(),
	}))))
	config.WarnDeprecated()
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
	poolCfg.ConnConfig.Tracer = tracing.PoolTracer()
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

	if *once {
		return runOnce(ctx, pool, natsClient, cfg)
	}

	logger := slog.Default()
	bus := event.NewBus(logger)
	registry := extension.NewManager(bus, logger)

	// Relay SBOM events to NATS so enrichment workers can pick them up.
	registry.Register(natspkg.NewRelayExtension(natsClient, cfg.NATSStreamName, logger))

	// Wire scanner worker: stateless scanner + outbox-pattern hint extension.
	// The scan_jobs row is the source of truth; NATS hints are a latency hint
	// and the DB poll loop is the fallback when hints are lost.
	jobSvc := service.NewJobService(pool, cfg.SecretBox)
	scannerSbomSvc := service.NewSBOMService(pool, bus, nil)
	sc := engine.NewSyftScanner(logger, cfg.ScannerGoSymbols)
	dispatcher := engine.NewDispatcher(sc, scannerSbomSvc, cfg.ScannerMaxImageBytes, cfg.EgressPolicy, logger)

	// Ingest commits each registry-scanned SBOM's root enrichment jobs in its own
	// transaction (ocidex-n1z4.1). The submitter, driven off the in-process
	// SBOMIngested event that fires here (not in the API), publishes the
	// enrich.hint so per-enricher workers pick the jobs up without waiting for
	// their poll loop.
	registry.Register(enrichment.NewNATSSubmitter(natsClient, cfg.NATSStreamName, logger))

	tracerProvider, stopTracing := tracing.Start(ctx, "ocidex-scanner-worker")
	defer stopTracing()
	meterProvider, metricsHandler, stopMetrics := metrics.Start(ctx, "ocidex-scanner-worker")
	defer stopMetrics()
	metrics.WatchPool(meterProvider, metrics.PoolMain, pool)
	natsClient.WithMetrics(meterProvider)

	workerID, _ := os.Hostname()
	scanProcessor := func(ctx context.Context, claim service.ScanJobClaim) error {
		req := scanner.ScanRequestFromClaim(claim)
		sbomID, err := dispatcher.ProcessOne(ctx, req)
		if err != nil {
			return err
		}
		return jobSvc.FinishByID(ctx, claim.ID, sbomID)
	}
	registry.Register(jobqueue.NewWorker(
		"scanner-hint",
		natsClient,
		cfg.NATSStreamName,
		jobSvc,
		scanProcessor,
		jobqueue.Config{
			WorkerID:          workerID,
			MaxConc:           cfg.ScannerMaxConcurrency,
			PollInterval:      cfg.ScannerPollInterval,
			JobTimeout:        scanTimeout,
			MaxAttempts:       int32(cfg.ScannerMaxAttempts), //nolint:gosec // G115: small bounded retry count
			StuckThreshold:    cfg.ScannerStuckThreshold,
			HintSubjectSuffix: scanner.ScanHintSubjectSuffix,
			HintDurable:       scanner.ScannerHintDurable,
		},
		logger,
	).WithMetrics(meterProvider, "scan").WithTracing(tracerProvider, "scan job"))

	// Wire catalog walk consumer: receives catalog.walk.requested from the API server poller
	// and performs the OCI catalog walk here in the scanner-worker.
	registrySvc := service.NewRegistryService(pool, cfg.SecretBox)
	natsSubmitter := scanner.NewNATSSubmitter(natsClient, cfg.NATSStreamName, jobSvc)
	registry.Register(scanner.NewNATSCatalogExtension(
		natsClient, registrySvc, scannerSbomSvc, natsSubmitter, cfg.NATSStreamName, cfg.EgressPolicy, logger,
	))

	if err := registry.InitAll(); err != nil {
		return fmt.Errorf("initializing extensions: %w", err)
	}

	extCtx, extCancel := context.WithCancel(context.Background())
	defer extCancel()

	if err := registry.StartAll(extCtx); err != nil {
		return fmt.Errorf("starting extensions: %w", err)
	}

	healthSrv := health.New(":9090", pool, natsClient, slog.Default()).WithMetrics(metricsHandler)
	healthSrv.Start()
	defer healthSrv.Stop()

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
func runOnce(ctx context.Context, pool *pgxpool.Pool, natsClient *natspkg.Client, cfg *config.Config) error {
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
	sc := engine.NewSyftScanner(logger, cfg.ScannerGoSymbols)

	// Ingest commits the root enrichment jobs itself (ocidex-n1z4.1); wire the
	// submitter onto the bus before ingest so the synchronous SBOMIngested event
	// also publishes the enrich.hint — same mechanism as the long-running worker.
	if err := enrichment.NewNATSSubmitter(natsClient, cfg.NATSStreamName, logger).Init(bus); err != nil {
		return fmt.Errorf("wiring enrichment submitter: %w", err)
	}

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

	// Use the same dispatcher path as the long-running worker: it fills image
	// metadata (architecture/build_date/version) from the manifest before scanning
	// — required by container-SBOM validation — and publishes SBOMIngested on the
	// bus, which the submitter wired above turns into enrichment jobs.
	dispatcher := engine.NewDispatcher(sc, sbomSvc, cfg.ScannerMaxImageBytes, cfg.EgressPolicy, logger)
	if _, err := dispatcher.ProcessOne(ctx, req); err != nil {
		return fmt.Errorf("processing scan: %w", err)
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
