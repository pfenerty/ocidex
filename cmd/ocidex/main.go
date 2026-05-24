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
	"github.com/pfenerty/ocidex/internal/enrichment/ocivalidate"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/extension"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
	"github.com/pfenerty/ocidex/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-version", "version":
			fmt.Printf("ocidex %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
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
	pool, err := setupDatabase(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	natsClient, err := setupNATSClient(cfg)
	if err != nil {
		return err
	}
	if natsClient != nil {
		defer natsClient.Close()
	}

	logger := slog.Default()
	bus := event.NewBus(logger)
	reg := extension.NewRegistry(bus, logger)

	registrySvc := service.NewRegistryService(pool)
	insecureResolver := service.BuildInsecureResolver(registrySvc)

	setupOptionalExts(cfg, reg, natsClient, logger)

	ociValidator := ocivalidate.NewValidator(ocivalidate.WithInsecureResolver(insecureResolver))
	sbomSvc := service.NewSBOMService(pool, bus, ociValidator)
	searchSvc := service.NewSearchService(pool)
	authSvc := service.NewAuthService(pool, cfg, bus)

	jobSvc := service.NewJobService(pool)
	scanSubmitter := setupScannerExt(cfg, pool, bus, reg, natsClient, logger, jobSvc)

	if err := reg.InitAll(); err != nil {
		return fmt.Errorf("initializing extensions: %w", err)
	}

	handler := api.NewHandler(sbomSvc, searchSvc, authSvc, registrySvc, jobSvc, pool, scanSubmitter, cfg)
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

	go runSessionCleaner(extCtx, authSvc)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
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

func setupDatabase(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing database config: %w", err)
	}
	if cfg.DatabaseMaxConns > 0 {
		poolCfg.MaxConns = int32(cfg.DatabaseMaxConns) //nolint:gosec // G115: value is a configured pool size
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	slog.Info("database connected")
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

func setupOptionalExts(cfg *config.Config, reg *extension.Registry, natsClient *natspkg.Client, logger *slog.Logger) {
	if cfg.AuditLogEnabled {
		reg.Register(audit.NewExtension(logger))
	}
	reg.Register(natspkg.NewRelayExtension(natsClient, cfg.NATSStreamName, logger))
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
func setupScannerExt(cfg *config.Config, _ *pgxpool.Pool, _ *event.Bus, _ *extension.Registry, natsClient *natspkg.Client, _ *slog.Logger, jobSvc service.JobService) api.ScanSubmitter {
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

// runMigrate dispatches `ocidex migrate up|down|status`. It deliberately
// avoids config.Load() because the migration tool has no business depending
// on NATS connectivity — only DATABASE_URL is required.
func runMigrate(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ocidex migrate up|down|status")
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
		return goose.Up(conn, "migrations")
	case "down":
		return goose.Down(conn, "migrations")
	case "status":
		return goose.Status(conn, "migrations")
	default:
		return fmt.Errorf("unknown migrate subcommand %q (want up|down|status)", args[0])
	}
}
