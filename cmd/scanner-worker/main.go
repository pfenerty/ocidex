// Package main is the entry point for the OCIDex scanner worker.
// It consumes scan requests from NATS JetStream, runs Syft, and ingests
// the resulting SBOMs.
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
	"github.com/pfenerty/ocidex/internal/health"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/scanner/engine"
	"github.com/pfenerty/ocidex/internal/service"
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
	registry := extension.NewManager(bus, logger)

	// Relay SBOM events to NATS so enrichment workers can pick them up.
	registry.Register(natspkg.NewRelayExtension(natsClient, cfg.NATSStreamName, logger))

	// Wire scanner worker: stateless scanner + outbox-pattern hint extension.
	// The scan_jobs row is the source of truth; NATS hints are a latency hint
	// and the DB poll loop is the fallback when hints are lost.
	jobSvc := service.NewJobService(pool)
	scannerSbomSvc := service.NewSBOMService(pool, bus, nil)
	sc := engine.NewSyftScanner(logger)
	dispatcher := engine.NewDispatcher(sc, scannerSbomSvc, logger)

	workerID, _ := os.Hostname()
	registry.Register(scanner.NewNATSHintExtension(
		natsClient,
		dispatcher,
		jobSvc,
		cfg.NATSStreamName,
		workerID,
		logger,
		cfg.ScannerMaxConcurrency,
		cfg.ScannerPollInterval,
		scanTimeout,
		cfg.ScannerMaxAttempts,
	))

	// Wire catalog walk consumer: receives catalog.walk.requested from the API server poller
	// and performs the OCI catalog walk here in the scanner-worker.
	registrySvc := service.NewRegistryService(pool)
	natsSubmitter := scanner.NewNATSSubmitter(natsClient, cfg.NATSStreamName, jobSvc)
	registry.Register(scanner.NewNATSCatalogExtension(
		natsClient, registrySvc, scannerSbomSvc, natsSubmitter, cfg.NATSStreamName, logger,
	))

	if err := registry.InitAll(); err != nil {
		return fmt.Errorf("initializing extensions: %w", err)
	}

	extCtx, extCancel := context.WithCancel(context.Background())
	defer extCancel()

	if err := registry.StartAll(extCtx); err != nil {
		return fmt.Errorf("starting extensions: %w", err)
	}

	healthSrv := health.New(":9090", pool, natsClient, slog.Default())
	healthSrv.Start()
	defer healthSrv.Stop()

	// Stuck-running sweep: any row stuck in 'running' past the stuck-threshold
	// is moved back to 'queued' (or 'failed' if retries are exhausted). This
	// replaces the NATS-aware orphan reconciler — under the outbox pattern the
	// DB row is the source of truth and no NATS-side reconciliation exists.
	stuckThreshold := cfg.ScannerStuckThreshold
	if err := jobSvc.RequeueStuckRunning(ctx, stuckThreshold, int32(cfg.ScannerMaxAttempts)); err != nil { //nolint:gosec // G115: small bounded retry count
		slog.Warn("startup stuck-running sweep failed", "err", err)
	}
	sweepCtx, sweepCancel := context.WithCancel(context.Background())
	defer sweepCancel()
	go runStuckRunningSweep(sweepCtx, jobSvc, stuckThreshold, int32(cfg.ScannerMaxAttempts)) //nolint:gosec // G115: as above

	// Purge old DLQ audit rows once per hour. The table is no longer written
	// to under the outbox model, but existing rows are retained for the admin
	// UI's failure-history view until SCAN_DLQ_RETENTION_DAYS expires them.
	if cfg.ScanDLQRetentionDays > 0 {
		purgeCtx, purgeCancel := context.WithCancel(context.Background())
		defer purgeCancel()
		retention := time.Duration(cfg.ScanDLQRetentionDays) * 24 * time.Hour
		go runDLQPurge(purgeCtx, jobSvc, retention, slog.Default())
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
	sc := engine.NewSyftScanner(logger)

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

// runStuckRunningSweep periodically requeues 'running' scan_jobs rows whose
// worker hasn't updated last_attempt_at within stuckThreshold. The row goes
// back to 'queued' for another worker to claim, or to 'failed' if its retry
// budget is exhausted. This is the only stuck-job sweep the outbox model
// needs — there is no NATS-side reconciler.
func runStuckRunningSweep(ctx context.Context, jobSvc service.JobService, stuckThreshold time.Duration, maxAttempts int32) {
	ticker := time.NewTicker(stuckThreshold / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := jobSvc.RequeueStuckRunning(ctx, stuckThreshold, maxAttempts); err != nil && ctx.Err() == nil {
				slog.Warn("stuck-running sweep failed", "err", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func runDLQPurge(ctx context.Context, jobSvc service.JobService, retention time.Duration, logger *slog.Logger) {
	purge := func() {
		n, err := jobSvc.PurgeOldFailures(ctx, retention)
		if err != nil {
			if ctx.Err() == nil {
				logger.Error("dlq purge failed", "err", err)
			}
			return
		}
		if n > 0 {
			logger.Info("dlq purge", "deleted", n, "retention_days", retention/(24*time.Hour))
		}
	}
	purge()
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if ctx.Err() != nil {
				return
			}
			purge()
		case <-ctx.Done():
			return
		}
	}
}
