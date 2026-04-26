package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const leaderRetryInterval = 30 * time.Second

// LeaderElect acquires a Postgres session-level advisory lock identified by key and calls fn
// while holding it. If the lock is already held by another backend, it retries every 30 s until
// ctx is cancelled. On ctx cancellation the lock is released before returning.
func LeaderElect(ctx context.Context, pool *pgxpool.Pool, key int64, fn func(context.Context)) {
	for {
		if ctx.Err() != nil {
			return
		}
		led, err := tryLead(ctx, pool, key, fn)
		if err != nil {
			slog.Error("leader election error", "lock_key", key, "err", err)
		}
		if led {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(leaderRetryInterval):
		}
	}
}

// tryLead tries once to acquire the advisory lock. Returns (true, nil) if fn ran to completion
// (i.e. we were leader and ctx was cancelled), (false, nil) if the lock was already held, or
// (false, err) on a database error.
func tryLead(ctx context.Context, pool *pgxpool.Pool, key int64, fn func(context.Context)) (bool, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return false, fmt.Errorf("acquire connection: %w", err)
	}

	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&acquired); err != nil {
		conn.Release()
		return false, fmt.Errorf("pg_try_advisory_lock: %w", err)
	}

	if !acquired {
		conn.Release()
		return false, nil
	}

	slog.Info("became leader", "lock_key", key)
	fn(ctx)

	// Use a fresh context: the parent ctx is already cancelled at this point.
	unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", key); err != nil {
		slog.Error("advisory lock release failed", "lock_key", key, "err", err)
	} else {
		slog.Info("released leader lock", "lock_key", key)
	}
	conn.Release()
	return true, nil
}
