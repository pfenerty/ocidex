// Command vuln-worker maintains the package-keyed vulnerability store by matching
// stored SBOMs against the grype vulnerability database (ADR-049). The leader
// (a Postgres advisory lock, so one replica writes at a time) checks for a newer
// database every VULN_REFRESH_INTERVAL and re-matches every SBOM when the build
// changes, writing each SBOM's matches as it goes so a restart resumes the pass;
// between builds it matches newly ingested SBOMs within a minute.
// Per-SBOM vulnerability status is derived by joining component.purl at read
// time, so a newly disclosed CVE reaches every affected SBOM without re-ingesting.
//
// Pass --once to run a single step (database check, then matching every SBOM not
// yet matched against the build) and exit (K8s Job / manual invocation).
package main

import (
	"context"
	"flag"
	"hash/fnv"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/health"
	"github.com/pfenerty/ocidex/internal/metrics"
	"github.com/pfenerty/ocidex/internal/service"
	"github.com/pfenerty/ocidex/internal/tracing"
	"github.com/pfenerty/ocidex/internal/vuln"
	"github.com/pfenerty/ocidex/internal/vuln/grypematch"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	once := flag.Bool("once", false, "Run a single refresh and exit")
	flag.Parse()

	cfg, err := config.LoadVulnWorker()
	if err != nil {
		return err
	}

	slog.SetDefault(slog.New(tracing.LogHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.SlogLevel(),
	}))))
	slog.Info("starting vuln-worker",
		"environment", cfg.Environment,
		"once", *once,
		"refresh_interval", cfg.RefreshInterval,
	)

	ctx := context.Background()
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	poolCfg.ConnConfig.Tracer = tracing.PoolTracer()
	if cfg.DatabaseMaxConns > 0 {
		poolCfg.MaxConns = int32(cfg.DatabaseMaxConns) //nolint:gosec // G115: configured pool size
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return err
	}
	slog.Info("database connected")

	store := vuln.NewPGStore(pool)
	db := grypematch.NewDB(grypematch.DBConfig{
		RootDir:   cfg.VulnDBDir,
		UpdateURL: cfg.VulnDBUpdateURL,
		MaxAge:    cfg.VulnDBMaxAge,
	}, slog.Default())
	defer func() { _ = db.Close() }()
	refresher := grypematch.NewRefresher(db, store, cfg.RefreshInterval, slog.Default())

	if *once {
		return refresher.Step(ctx)
	}

	if !cfg.RefreshEnabled {
		slog.Info("vuln refresh disabled (VULN_REFRESH_ENABLED=false); idling")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if cfg.RefreshEnabled {
		h := fnv.New64a()
		_, _ = h.Write([]byte("ocidex-vuln-refresh"))
		lockKey := int64(h.Sum64()) //nolint:gosec // G115: advisory lock key
		go service.LeaderElect(runCtx, pool, lockKey, refresher.Run)
		slog.Info("vuln refresh election started", "lock_key", lockKey)
	}

	_, stopTracing := tracing.Start(ctx, "ocidex-vuln-worker")
	defer stopTracing()
	meterProvider, metricsHandler, stopMetrics := metrics.Start(ctx, "ocidex-vuln-worker")
	defer stopMetrics()
	metrics.WatchPool(meterProvider, metrics.PoolMain, pool)
	healthSrv := health.New(":9090", pool, nil, slog.Default()).WithMetrics(metricsHandler)
	healthSrv.Start()
	defer healthSrv.Stop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("shutdown signal received", "signal", sig)

	cancel()
	// Give the leader loop a moment to release its advisory lock.
	time.Sleep(200 * time.Millisecond)
	slog.Info("vuln-worker stopped")
	return nil
}
