package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Server is the private /metrics listener the API runs beside its public one
// (ADR-0054 M2). Workers serve /metrics from their health server instead.
type Server struct {
	srv    *http.Server
	logger *slog.Logger
}

// NewServer returns a Server that serves p's handler at /metrics on addr.
func NewServer(addr string, p *Provider, logger *slog.Logger) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", p.Handler())
	return &Server{
		srv: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
		logger: logger,
	}
}

// Handler is the server's mux, for tests that serve it without listening.
func (s *Server) Handler() http.Handler { return s.srv.Handler }

// Start listens in a goroutine. A listen failure is logged, not fatal: losing
// metrics must not take the API down.
func (s *Server) Start() {
	go func() {
		s.logger.Info("metrics listening", "addr", s.srv.Addr)
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("metrics server", "err", err)
		}
	}()
}

// Stop shuts the listener down, waiting at most until ctx is done.
func (s *Server) Stop(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
