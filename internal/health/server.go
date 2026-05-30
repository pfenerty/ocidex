// Package health provides a tiny HTTP health server for the worker binaries.
// The API binary uses chi/huma routes instead — this package targets workers
// that have no other HTTP surface but still need k8s liveness/readiness probes.
package health

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	natspkg "github.com/pfenerty/ocidex/internal/nats"
)

// Server exposes /healthz (liveness) and /readyz (readiness).
type Server struct {
	addr   string
	pool   *pgxpool.Pool
	nats   *natspkg.Client
	srv    *http.Server
	logger *slog.Logger
}

// New returns a Server bound to addr (e.g. ":9090"). pool and nats may be nil;
// readyz reports OK only when every supplied dependency is healthy.
func New(addr string, pool *pgxpool.Pool, nats *natspkg.Client, logger *slog.Logger) *Server {
	return &Server{addr: addr, pool: pool, nats: nats, logger: logger}
}

// Start spins up the HTTP server in a goroutine. Call Stop to shut it down.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	s.srv = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("health server", "err", err)
		}
	}()
}

// Stop gracefully shuts down the health server.
func (s *Server) Stop() {
	if s.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.nats != nil && !s.nats.Connected() {
		http.Error(w, "nats disconnected", http.StatusServiceUnavailable)
		return
	}
	if s.pool != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()
		if err := s.pool.Ping(ctx); err != nil {
			http.Error(w, "db ping failed", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
