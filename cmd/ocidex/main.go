// Package main is the entry point for the OCIDex server.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/pfenerty/ocidex/db"
	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/audit"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/dbaudit"
	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/enrichment/ocivalidate"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/extension"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
	"github.com/pfenerty/ocidex/internal/version"
	"github.com/pfenerty/ocidex/internal/vuln"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-version", "version":
			fmt.Printf("ocidex %s\n", version.String())
			return
		case "migrate":
			if err := runMigrate(os.Args[2:]); err != nil {
				slog.Error("migrate failed", "err", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := validateOAuthConfig(cfg); err != nil {
		return err
	}

	// Initialize structured logging.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.SlogLevel(),
	})))
	slog.Info("starting ocidex",
		"port", cfg.Port,
		"environment", cfg.Environment,
		"log_level", cfg.LogLevel,
	)

	ctx := context.Background()
	pool, bgPool, err := setupDatabase(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	defer bgPool.Close()

	natsClient, err := setupNATSClient(cfg)
	if err != nil {
		return err
	}
	if natsClient != nil {
		defer natsClient.Close()
	}

	logger := slog.Default()
	bus := event.NewBus(logger)
	reg := extension.NewManager(bus, logger)

	registrySvc := service.NewRegistryService(pool)
	namespaceSvc := service.NewNamespaceService(pool)
	sourceSvc := service.NewSourceService(pool)
	insecureResolver := service.BuildInsecureHostLookup(registrySvc)

	setupOptionalExts(cfg, reg, natsClient, logger)

	ociValidator := ocivalidate.NewValidator(ocivalidate.WithInsecureResolver(insecureResolver))
	sbomSvc := service.NewSBOMService(pool, bus, ociValidator)
	searchSvc := service.NewSearchService(pool, service.WithWarmDB(bgPool))
	authSvc := service.NewAuthService(pool, cfg, bus)

	jobSvc := service.NewJobService(pool)
	// The API enqueues and administers enrichment jobs but never claims one, so
	// the ClaimNext partition name is empty (see NewEnrichJobService).
	enrichJobSvc := service.NewEnrichJobService(pool, "")
	scanSubmitter := setupScannerExt(cfg, pool, bus, reg, natsClient, logger, jobSvc)
	setupEnrichmentSubmitter(cfg, reg, natsClient, logger, enrichJobSvc)
	setupIngestVulnLookup(cfg, pool, reg, logger)

	if err := reg.InitAll(); err != nil {
		return fmt.Errorf("initializing extensions: %w", err)
	}

	handler := api.NewHandler(sbomSvc, searchSvc, authSvc, registrySvc, namespaceSvc, sourceSvc, jobSvc, enrichJobSvc, pool, scanSubmitter, cfg)
	router := api.NewRouter(handler, cfg.CORSAllowedOrigins, cfg.FrontendURL, cfg.APIBaseURL)

	extCtx, extCancel := context.WithCancel(context.Background())
	defer extCancel()
	if err := reg.StartAll(extCtx); err != nil {
		return fmt.Errorf("starting extensions: %w", err)
	}

	if cfg.ScannerEnabled && cfg.RegistryPollerEnabled && scanSubmitter != nil {
		walker := setupRegistryWalker(cfg, natsClient, scanSubmitter, sbomSvc, logger)
		poller := scanner.NewPoller(registrySvc, walker, logger)
		h := fnv.New64a()
		h.Write([]byte("ocidex-poller"))
		pollerKey := int64(h.Sum64()) //nolint:gosec
		go service.LeaderElect(extCtx, pool, pollerKey, poller.Run)
		slog.Info("registry poller election started", "lock_key", pollerKey)
	} else {
		warnUnpolledRegistries(ctx, registrySvc)
	}

	if cfg.ProvenanceReverifierEnabled {
		reverifier := enrichment.NewReverifier(repository.New(pool), cfg.ProvenanceRecheckInterval, logger)
		rh := fnv.New64a()
		rh.Write([]byte("ocidex-reverifier"))
		reverifierKey := int64(rh.Sum64()) //nolint:gosec
		go service.LeaderElect(extCtx, pool, reverifierKey, reverifier.Run)
		slog.Info("provenance reverifier election started", "lock_key", reverifierKey, "interval", cfg.ProvenanceRecheckInterval)
	} else {
		slog.Info("provenance reverifier disabled")
	}

	go runSessionCleaner(extCtx, authSvc)

	// The dashboard aggregates take longer than any request timeout allows, so
	// they are computed out-of-band and served from cache. Per-process cache,
	// so this runs on every replica rather than behind leader election. It gets
	// its own search service on the small background pool so a warm pass can
	// never occupy connections the request path needs.
	statsWarmer := service.NewStatsWarmer(searchSvc, service.StatsWarmInterval, logger)
	go statsWarmer.Run(extCtx)
	slog.Info("dashboard stats warmer started", "interval", service.StatsWarmInterval)

	// The list pages read precomputed rollups rather than aggregating the
	// component table per request. Unlike the stats cache these are shared
	// database state, so every replica runs the refresher and an advisory lock
	// inside the pass decides which one actually does the work. It shares the
	// background pool with the warmer for the same reason: a refresh must never
	// hold a connection the request path needs.
	rollupRefresher := service.NewRollupRefresher(bgPool, service.RollupRefreshInterval, logger)
	go rollupRefresher.Run(extCtx)
	slog.Info("rollup refresher started",
		"backstop_interval", service.RollupRefreshInterval,
		"poll_interval", service.RollupPollInterval,
		"lock_key", rollupRefresher.LockKey())

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: router,
		// WriteTimeout must exceed the chi request timeout in api.NewRouter:
		// if it doesn't, a slow handler has its connection dropped before the
		// middleware can turn the deadline into a response the client renders.
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := serveAndWait(srv); err != nil {
		return err
	}

	extCancel()
	if err := reg.StopAll(); err != nil {
		slog.Error("extension shutdown error", "err", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}
	slog.Info("server stopped")
	return nil
}

// backgroundPoolMaxConns bounds the pool used by out-of-band work (the stats
// warmer and rollup refresher). It is deliberately tiny and separate from the
// request pool: those jobs run multi-minute aggregates, and when they shared
// the request pool they held every connection continuously, so HTTP handlers
// queued for a connection until they hit the 30s request timeout.
//
// Three, not two: a refresh pass holds one connection for the length of its
// transaction, and the warmer runs two aggregates at a time. At two the
// refresher would silently halve the warmer's concurrency whenever it ran.
const backgroundPoolMaxConns = 3

// setupDatabase opens the request pool and the small background pool. Callers
// must close both.
func setupDatabase(ctx context.Context, cfg *config.Config) (request, background *pgxpool.Pool, err error) {
	var requestMaxConns int32
	if cfg.DatabaseMaxConns > 0 {
		requestMaxConns = int32(cfg.DatabaseMaxConns) //nolint:gosec // G115: value is a configured pool size
	}
	request, err = openPool(ctx, cfg.DatabaseURL, requestMaxConns)
	if err != nil {
		return nil, nil, fmt.Errorf("opening request pool: %w", err)
	}
	background, err = openPool(ctx, cfg.DatabaseURL, backgroundPoolMaxConns)
	if err != nil {
		request.Close()
		return nil, nil, fmt.Errorf("opening background pool: %w", err)
	}
	slog.Info("database connected", "background_max_conns", backgroundPoolMaxConns)
	return request, background, nil
}

// openPool connects a pool and verifies it, overriding MaxConns when maxConns
// is positive so the pgx default stands otherwise.
func openPool(ctx context.Context, url string, maxConns int32) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parsing database config: %w", err)
	}
	if maxConns > 0 {
		poolCfg.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	return pool, nil
}

func setupNATSClient(cfg *config.Config) (*natspkg.Client, error) {
	client, err := natspkg.Connect(natspkg.Config{
		URL:           cfg.NATSURL,
		StreamName:    cfg.NATSStreamName,
		EventTTLHours: cfg.NATSEventTTL,
		Replicas:      cfg.NATSStreamReplicas,
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS: %w", err)
	}
	slog.Info("NATS connected", "url", cfg.NATSURL, "stream", cfg.NATSStreamName)
	return client, nil
}

func validateOAuthConfig(cfg *config.Config) error {
	if cfg.GitHubClientID == "" || cfg.GitHubClientSecret == "" || cfg.SessionSecret == "" {
		return fmt.Errorf("GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, and SESSION_SECRET are required")
	}
	return nil
}

func warnUnpolledRegistries(ctx context.Context, registrySvc service.RegistryService) {
	pollable, err := registrySvc.ListPollable(ctx)
	if err == nil && len(pollable) > 0 {
		slog.Warn("poll-mode registries exist but registry poller will not run",
			"count", len(pollable),
			"hint", "set SCANNER_ENABLED=true and REGISTRY_POLLER_ENABLED=true")
	}
}

func setupIngestVulnLookup(cfg *config.Config, pool *pgxpool.Pool, reg *extension.Manager, logger *slog.Logger) {
	store := vuln.NewPGStore(pool)
	client := vuln.NewClient(
		vuln.WithBaseURL(cfg.OSVBaseURL),
		vuln.WithHTTPClient(&http.Client{Timeout: cfg.OSVTimeout}),
		vuln.WithBatchSize(cfg.OSVBatchSize),
	)
	refresher := vuln.NewRefreshService(store, client, logger)
	reg.Register(vuln.NewIngestVulnExtension(store, refresher, logger, cfg.IngestVulnLookupEnabled, cfg.IngestVulnLookupMaxConcurrency))
}

func setupOptionalExts(cfg *config.Config, reg *extension.Manager, natsClient *natspkg.Client, logger *slog.Logger) {
	if cfg.AuditLogEnabled {
		reg.Register(audit.NewExtension(logger))
	}
	reg.Register(natspkg.NewRelayExtension(natsClient, cfg.NATSStreamName, logger))
}

func setupEnrichmentSubmitter(cfg *config.Config, reg *extension.Manager, natsClient *natspkg.Client, logger *slog.Logger, jobSvc service.EnrichJobService) {
	reg.Register(enrichment.NewNATSSubmitter(natsClient, cfg.NATSStreamName, jobSvc, logger))
}

func setupRegistryWalker(cfg *config.Config, natsClient *natspkg.Client, sub api.ScanSubmitter, dl scanner.DigestLister, logger *slog.Logger) scanner.RegistryWalker {
	if natsClient != nil {
		return scanner.NewNATSCatalogPublisher(natsClient, cfg.NATSStreamName)
	}
	return scanner.NewDirectWalker(sub, dl, logger)
}

// setupScannerExt wires the NATS scan submitter when scanning is enabled.
// The API server never scans in-process: it only publishes scan requests to
// NATS, so that syft and its transitive deps stay out of the API binary. A
// dedicated scanner-worker process consumes the requests and runs the scan.
func setupScannerExt(cfg *config.Config, _ *pgxpool.Pool, _ *event.Bus, _ *extension.Manager, natsClient *natspkg.Client, _ *slog.Logger, jobSvc service.JobService) api.ScanSubmitter {
	if !cfg.ScannerEnabled {
		return nil
	}
	return scanner.NewNATSSubmitter(natsClient, cfg.NATSStreamName, jobSvc)
}

func runSessionCleaner(ctx context.Context, authSvc service.AuthService) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = authSvc.CleanExpiredSessions(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func serveAndWait(srv *http.Server) error {
	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("shutdown signal received", "signal", sig)
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// runMigrate dispatches `ocidex migrate up|down|status|audit`. It deliberately
// avoids config.Load() because the migration tool has no business depending
// on NATS connectivity — only DATABASE_URL is required.
func runMigrate(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ocidex migrate up|down|status|audit")
	}
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	conn, err := sql.Open("pgx", dbURL)
	if err != nil {
		return fmt.Errorf("opening db: %w", err)
	}
	defer conn.Close()

	goose.SetBaseFS(db.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting dialect: %w", err)
	}

	switch args[0] {
	case "up":
		if err := ownershipPreflight(context.Background(), conn); err != nil {
			return err
		}
		return goose.Up(conn, "migrations")
	case "down":
		return goose.Down(conn, "migrations")
	case "status":
		return goose.Status(conn, "migrations")
	case "audit":
		return ownershipPreflight(context.Background(), conn)
	default:
		return fmt.Errorf("unknown migrate subcommand %q (want up|down|status|audit)", args[0])
	}
}

// ownershipPreflight fails the migration before goose touches the schema if any
// public-schema object is owned by another role. Such objects — created by hand
// as a superuser rather than by a migration — cannot be replaced, dropped,
// altered or truncated by the app role, so both the migration and the runtime
// paths that use them fail, the latter silently as HTTP 500s. Only a superuser
// can repair it, so the check reports the exact ALTER statements and stops.
//
// Set OCIDEX_MIGRATE_SKIP_OWNERSHIP_CHECK=1 to bypass, for the case where the
// check itself is wrong and a deploy must go out regardless.
func ownershipPreflight(ctx context.Context, conn *sql.DB) error {
	if os.Getenv("OCIDEX_MIGRATE_SKIP_OWNERSHIP_CHECK") == "1" {
		slog.Warn("ownership preflight skipped by OCIDEX_MIGRATE_SKIP_OWNERSHIP_CHECK")
		return nil
	}
	role, err := dbaudit.CurrentUser(ctx, conn)
	if err != nil {
		return err
	}
	objs, err := dbaudit.Misowned(ctx, conn)
	if err != nil {
		return err
	}
	if len(objs) == 0 {
		slog.Info("ownership preflight passed", "role", role)
		return nil
	}
	return fmt.Errorf("ownership preflight failed:\n\n%s", dbaudit.Report(objs, role))
}
