// Package main is the entry point for the OCIDex server.
package main

import (
	"context"
	"database/sql"
	"fmt"
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
	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/enrichment/oci"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/extension"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/repository"
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

	setupEnrichmentExt(cfg, reg, pool, insecureResolver, natsClient, logger)
	setupOptionalExts(cfg, reg, natsClient, logger)

	ociValidator := oci.NewValidator(oci.WithInsecureResolver(insecureResolver))
	sbomSvc := service.NewSBOMService(pool, bus, ociValidator)
	searchSvc := service.NewSearchService(pool)
	authSvc := service.NewAuthService(pool, cfg)

	scanSubmitter := setupScannerExt(cfg, pool, bus, reg, natsClient, logger)

	if err := reg.InitAll(); err != nil {
		return fmt.Errorf("initializing extensions: %w", err)
	}

	handler := api.NewHandler(sbomSvc, searchSvc, authSvc, registrySvc, pool, scanSubmitter, cfg)
	router := api.NewRouter(handler, cfg.CORSAllowedOrigins, cfg.FrontendURL, cfg.APIBaseURL)

	extCtx, extCancel := context.WithCancel(context.Background())
	defer extCancel()
	if err := reg.StartAll(extCtx); err != nil {
		return fmt.Errorf("starting extensions: %w", err)
	}

	if cfg.ScannerEnabled && cfg.RegistryPollerEnabled && scanSubmitter != nil {
		poller := scanner.NewPoller(registrySvc, scanSubmitter, logger)
		go poller.Run(extCtx)
		slog.Info("registry poller started")
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
	if err := runMigrations(cfg.DatabaseURL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return pool, nil
}

func setupNATSClient(cfg *config.Config) (*natspkg.Client, error) {
	if !cfg.NATSEnabled {
		return nil, nil
	}
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

func setupOptionalExts(cfg *config.Config, reg *extension.Registry, natsClient *natspkg.Client, logger *slog.Logger) {
	if cfg.AuditLogEnabled {
		reg.Register(audit.NewExtension(logger))
	}
	if cfg.NATSEnabled {
		reg.Register(natspkg.NewRelayExtension(natsClient, cfg.NATSStreamName, logger))
	}
}

func setupEnrichmentExt(cfg *config.Config, reg *extension.Registry, pool *pgxpool.Pool, insecureResolver func(string) bool, natsClient *natspkg.Client, logger *slog.Logger) {
	if cfg.NATSEnabled && cfg.EnrichmentNATSMode {
		return
	}
	if !cfg.EnrichmentEnabled {
		return
	}
	enrichStore := repository.New(pool)
	ociEnricher := oci.NewEnricher(oci.WithInsecureResolver(insecureResolver))
	dispatcher := enrichment.NewDispatcher(
		enrichStore,
		[]enrichment.Enricher{ociEnricher},
		enrichment.WithWorkers(cfg.EnrichmentWorkers),
		enrichment.WithQueueSize(cfg.EnrichmentQueueSize),
	)
	if cfg.NATSEnabled {
		reg.Register(enrichment.NewNATSExtension(natsClient, dispatcher, cfg.NATSStreamName, logger))
	} else {
		reg.Register(enrichment.NewExtension(dispatcher))
	}
}

func setupScannerExt(cfg *config.Config, pool *pgxpool.Pool, bus *event.Bus, reg *extension.Registry, natsClient *natspkg.Client, logger *slog.Logger) api.ScanSubmitter {
	if !cfg.ScannerEnabled {
		return nil
	}
	// Use nil validator: webhook confirms image exists at a known digest.
	scannerSbomSvc := service.NewSBOMService(pool, bus, nil)
	sc := scanner.NewScanner(logger)
	if cfg.NATSEnabled && cfg.ScannerNATSMode {
		// External workers consume from NATS — main process only publishes.
		return scanner.NewNATSSubmitter(natsClient, cfg.NATSStreamName, logger)
	}
	// In-process mode.
	scanDispatcher := scanner.NewDispatcher(sc, scannerSbomSvc, cfg.ScannerWorkers, cfg.ScannerQueueSize, logger)
	reg.Register(scanner.NewExtension(scanDispatcher))
	return scanDispatcher
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

func runMigrations(databaseURL string) error {
	conn, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("opening migration connection: %w", err)
	}
	defer conn.Close()

	goose.SetBaseFS(db.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting dialect: %w", err)
	}

	if err := goose.Up(conn, "migrations"); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	slog.Info("migrations complete")
	return nil
}
