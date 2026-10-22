package metrics

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Pool names for the pool attribute: the request pool every binary has, and
// the API's small pool for out-of-band work.
const (
	PoolMain       = "main"
	PoolBackground = "background"
)

// PoolStats is the subset of pgxpool.Stat the pool instruments report.
type PoolStats struct {
	Acquired, Idle, Total, Max                            int32
	AcquireCount, EmptyAcquireCount, CanceledAcquireCount int64
	EmptyAcquireWait                                      time.Duration
}

// StatsOf reads PoolStats from a pgxpool.
func StatsOf(p *pgxpool.Pool) func() PoolStats {
	return func() PoolStats {
		s := p.Stat()
		return PoolStats{
			Acquired:             s.AcquiredConns(),
			Idle:                 s.IdleConns(),
			Total:                s.TotalConns(),
			Max:                  s.MaxConns(),
			AcquireCount:         s.AcquireCount(),
			EmptyAcquireCount:    s.EmptyAcquireCount(),
			CanceledAcquireCount: s.CanceledAcquireCount(),
			EmptyAcquireWait:     s.EmptyAcquireWaitTime(),
		}
	}
}

// ObservePool reports a connection pool's stats on mp under pool (PoolMain or
// PoolBackground) each time metrics are collected (ADR-0054 M5):
// ocidex.db.pool.connections {state}, ocidex.db.pool.acquires {outcome} and
// ocidex.db.pool.acquire_wait.
func ObservePool(mp metric.MeterProvider, pool string, stats func() PoolStats) (metric.Registration, error) {
	m := Meter(mp)
	conns, err := m.Int64ObservableGauge("ocidex.db.pool.connections",
		metric.WithDescription("Database pool connections, by state."),
		metric.WithUnit("{connection}"))
	if err != nil {
		return nil, err
	}
	acquires, err := m.Int64ObservableCounter("ocidex.db.pool.acquires",
		metric.WithDescription("Successful and canceled connection acquires; waited means the pool had no idle connection."),
		metric.WithUnit("{acquire}"))
	if err != nil {
		return nil, err
	}
	wait, err := m.Float64ObservableCounter("ocidex.db.pool.acquire_wait",
		metric.WithDescription("Total time acquires spent waiting for a connection."),
		metric.WithUnit("s"))
	if err != nil {
		return nil, err
	}

	poolAttr := attribute.String("pool", pool)
	with := func(k, v string) metric.MeasurementOption {
		return metric.WithAttributes(poolAttr, attribute.String(k, v))
	}
	return m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		s := stats()
		o.ObserveInt64(conns, int64(s.Acquired), with("state", "acquired"))
		o.ObserveInt64(conns, int64(s.Idle), with("state", "idle"))
		o.ObserveInt64(conns, int64(s.Total), with("state", "total"))
		o.ObserveInt64(conns, int64(s.Max), with("state", "max"))
		o.ObserveInt64(acquires, s.EmptyAcquireCount, with("outcome", "waited"))
		o.ObserveInt64(acquires, s.AcquireCount-s.EmptyAcquireCount, with("outcome", "immediate"))
		o.ObserveInt64(acquires, s.CanceledAcquireCount, with("outcome", "canceled"))
		o.ObserveFloat64(wait, s.EmptyAcquireWait.Seconds(), metric.WithAttributes(poolAttr))
		return nil
	}, conns, acquires, wait)
}

// WatchPool is ObservePool for a pgxpool, logging a registration failure
// rather than returning it: losing metrics must not take a binary down.
func WatchPool(mp metric.MeterProvider, pool string, p *pgxpool.Pool) {
	if _, err := ObservePool(mp, pool, StatsOf(p)); err != nil {
		slog.Error("db pool metrics disabled", "pool", pool, "err", err)
	}
}
