package service

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func requireDockerLeader(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker not available, skipping leader election test")
	}
}

func setupLeaderTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := t.Context()

	pgContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("leader_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("starting postgres container: %v", err)
	}
	t.Cleanup(func() { _ = pgContainer.Terminate(context.Background()) })

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("getting connection string: %v", err)
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("creating pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestLeaderElect_AcquiresAndRelease(t *testing.T) {
	requireDockerLeader(t)
	is := is.New(t)
	pool := setupLeaderTestDB(t)

	const key int64 = 12345

	fnCalled := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan struct{})
	go func() {
		defer close(done)
		LeaderElect(ctx, pool, key, func(ctx context.Context) {
			close(fnCalled)
			<-ctx.Done()
		})
	}()

	select {
	case <-fnCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("fn was not called within 5 s")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("LeaderElect did not return after context cancellation")
	}

	// Lock must be released: a fresh connection should be able to acquire it.
	var acquired bool
	err := pool.QueryRow(context.Background(), "SELECT pg_try_advisory_lock($1)", key).Scan(&acquired)
	is.NoErr(err)
	is.True(acquired)
	_, _ = pool.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", key)
}

func TestLeaderElect_OnlyOneLeader(t *testing.T) {
	requireDockerLeader(t)
	is := is.New(t)
	pool := setupLeaderTestDB(t)

	const key int64 = 99999

	// Pre-acquire the lock on a dedicated connection to block the poller.
	blocker, err := pool.Acquire(t.Context())
	is.NoErr(err)
	var ok bool
	err = blocker.QueryRow(t.Context(), "SELECT pg_try_advisory_lock($1)", key).Scan(&ok)
	is.NoErr(err)
	is.True(ok)

	fnCalled := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		LeaderElect(ctx, pool, key, func(ctx context.Context) {
			fnCalled <- struct{}{}
			<-ctx.Done()
		})
	}()

	// fn should NOT be called while the lock is held elsewhere.
	select {
	case <-fnCalled:
		t.Fatal("fn was called despite lock being held by another connection")
	case <-time.After(1 * time.Second):
	}

	// Release the blocker; the goroutine should acquire within leaderRetryInterval + margin.
	_, err = blocker.Exec(t.Context(), "SELECT pg_advisory_unlock($1)", key)
	is.NoErr(err)
	blocker.Release()

	select {
	case <-fnCalled:
	case <-time.After(35 * time.Second):
		t.Fatal("fn was not called within 35 s after lock was released")
	}
}
