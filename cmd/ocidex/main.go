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
	"strings"
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

	// OAuth fields are required for the API binary.
	if cfg.GitHubClientID == "" || cfg.GitHubClientSecret == "" || cfg.SessionSecret == "" {
		return fmt.Errorf("GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, and SESSION_SECRET are required")
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

	// Connect to PostgreSQL.
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

	// Run migrations.
	if err := runMigrations(cfg.DatabaseURL); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	// Optionally connect to NATS JetStream.
	var natsClient *natspkg.Client
	if cfg.NATSEnabled {
		natsClient, err = natspkg.Connect(natspkg.Config{
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
	}

	// Wire event bus and extension registry.
	logger := slog.Default()
	bus := event.NewBus(logger)
	registry := extension.NewRegistry(bus, logger)

	// Registry service must be created before OCI enricher/validator so the
	// insecure resolver closure can look up per-registry HTTP settings.
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

	if cfg.NATSEnabled && cfg.EnrichmentNATSMode {
		// Enrichment-worker processes consume from NATS; API only publishes via relay.
		// No NATSExtension registered here.
	} else if cfg.EnrichmentEnabled {
		enrichStore := repository.New(pool)
		ociEnricher := oci.NewEnricher(oci.WithInsecureResolver(insecureResolver))
		dispatcher := enrichment.NewDispatcher(
			enrichStore,
			[]enrichment.Enricher{ociEnricher},
			enrichment.WithWorkers(cfg.EnrichmentWorkers),
			enrichment.WithQueueSize(cfg.EnrichmentQueueSize),
		)
		if cfg.NATSEnabled {
			registry.Register(enrichment.NewNATSExtension(natsClient, dispatcher, logger))
		} else {
			registry.Register(enrichment.NewExtension(dispatcher))
		}
	}

	if cfg.AuditLogEnabled {
		registry.Register(audit.NewExtension(logger))
	}

	if cfg.NATSEnabled {
		registry.Register(natspkg.NewRelayExtension(natsClient, logger))
	}

	// Wire core services.
	ociValidator := oci.NewValidator(oci.WithInsecureResolver(insecureResolver))
	sbomSvc := service.NewSBOMService(pool, bus, ociValidator)
	searchSvc := service.NewSearchService(pool)
	authSvc := service.NewAuthService(pool, cfg)

	var scanSubmitter api.ScanSubmitter
	if cfg.ScannerEnabled {
		// Use nil validator: webhook confirms image exists at a known digest.
		scannerSbomSvc := service.NewSBOMService(pool, bus, nil)
		sc := scanner.NewScanner(logger)

		if cfg.NATSEnabled && cfg.ScannerNATSMode {
			// External workers consume from NATS — main process only publishes.
			scanSubmitter = scanner.NewNATSSubmitter(natsClient, logger)
		} else {
			// In-process mode.
			scanDispatcher := scanner.NewDispatcher(sc, scannerSbomSvc, cfg.ScannerWorkers, cfg.ScannerQueueSize, logger)
			registry.Register(scanner.NewExtension(scanDispatcher))
			scanSubmitter = scanDispatcher
		}
	}

	if err := registry.InitAll(); err != nil {
		return fmt.Errorf("initializing extensions: %w", err)
	}

	handler := api.NewHandler(sbomSvc, searchSvc, authSvc, registrySvc, pool, scanSubmitter, cfg)
	router := api.NewRouter(handler, cfg.CORSAllowedOrigins, cfg.APIBaseURL)

	// Start extensions.
	extCtx, extCancel := context.WithCancel(context.Background())
	defer extCancel()
	if err := registry.StartAll(extCtx); err != nil {
		return fmt.Errorf("starting extensions: %w", err)
	}

	if cfg.ScannerEnabled && cfg.RegistryPollerEnabled && scanSubmitter != nil {
		poller := scanner.NewPoller(registrySvc, scanSubmitter, logger)
		go poller.Run(extCtx)
		slog.Info("registry poller started")
	}

	// Periodically purge expired sessions.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = authSvc.CleanExpiredSessions(extCtx)
			case <-extCtx.Done():
				return
			}
		}
	}()

	// Start HTTP server.
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown.
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

	// Stop extensions first (enrichment workers, etc.).
	extCancel()
	if err := registry.StopAll(); err != nil {
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
