// Command vuln-worker maintains the package-keyed vulnerability store. It runs a
// scheduled refresh (guarded by a Postgres advisory lock so only one replica
// refreshes at a time) that queries every distinct component purl against OSV.dev
// and rebuilds the purl->vulnerability mappings. Per-SBOM vulnerability status is
// derived by joining component.purl at read time, so a newly disclosed CVE filters
// up to every affected SBOM without re-enriching it.
//
// Pass --once to run a single refresh and exit (K8s Job / manual invocation).
package main

import (
	"context"
	"flag"
	"hash/fnv"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/health"
	"github.com/pfenerty/ocidex/internal/service"
	"github.com/pfenerty/ocidex/internal/vuln"
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

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.SlogLevel(),
	})))
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
	osvClient := vuln.NewClient(
		vuln.WithBaseURL(cfg.OSVBaseURL),
		vuln.WithHTTPClient(&http.Client{Timeout: cfg.OSVTimeout}),
		vuln.WithBatchSize(cfg.OSVBatchSize),
	)
	refresher := vuln.NewRefreshService(store, osvClient, slog.Default())

	if *once {
		return refresher.Refresh(ctx)
	}

	if !cfg.RefreshEnabled {
		slog.Info("vuln refresh disabled (VULN_REFRESH_ENABLED=false); idling")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if cfg.RefreshEnabled {
		scheduler := vuln.NewScheduler(refresher, store, cfg.RefreshInterval, slog.Default())
		h := fnv.New64a()
		_, _ = h.Write([]byte("ocidex-vuln-refresh"))
		lockKey := int64(h.Sum64()) //nolint:gosec // G115: advisory lock key
		go service.LeaderElect(runCtx, pool, lockKey, scheduler.Run)
		slog.Info("vuln refresh election started", "lock_key", lockKey)
	}

	healthSrv := health.New(":9090", pool, nil, slog.Default())
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
