package scanner_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/scanner"
)

func startedWalks(t *testing.T, maxConcurrent int) *scanner.AdhocWalks {
	t.Helper()
	a := scanner.NewAdhocWalks(maxConcurrent, time.Minute, slog.Default())
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Stop() })
	return a
}

// Concurrent requests for one registry run one walk (ocidex-89c9.2).
func TestAdhocWalksDedupe(t *testing.T) {
	is := is.New(t)
	a := startedWalks(t, 4)

	release := make(chan struct{})
	var runs atomic.Int32
	var finished sync.WaitGroup
	finished.Add(2) // reg-1 once, reg-2 once
	walk := func(context.Context) {
		defer finished.Done()
		runs.Add(1)
		<-release
	}

	const callers = 16
	var accepted, refused atomic.Int32
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := a.Run("reg-1", walk); {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, scanner.ErrWalkInProgress):
				refused.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	is.Equal(accepted.Load(), int32(1))
	is.Equal(refused.Load(), int32(callers-1))

	// A different registry is not held up by the first.
	is.NoErr(a.Run("reg-2", walk))

	close(release)
	finished.Wait()
	is.Equal(runs.Load(), int32(2))

	// Once the walk has finished, the registry can be walked again. Run
	// returns before the coordinator forgets the key, so retry briefly.
	done := make(chan struct{})
	for errors.Is(a.Run("reg-1", func(context.Context) { close(done) }), scanner.ErrWalkInProgress) {
		time.Sleep(time.Millisecond)
	}
	<-done
}

// No more than maxConcurrent walks run at once; the rest wait their turn.
func TestAdhocWalksConcurrencyBound(t *testing.T) {
	is := is.New(t)
	a := startedWalks(t, 2)

	release := make(chan struct{})
	var cur, peak, finished atomic.Int32
	var all sync.WaitGroup
	all.Add(5)
	walk := func(context.Context) {
		defer all.Done()
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		cur.Add(-1)
		finished.Add(1)
	}
	for _, key := range []string{"a", "b", "c", "d", "e"} {
		is.NoErr(a.Run(key, walk))
	}
	time.Sleep(50 * time.Millisecond) // let every goroutine reach the semaphore
	is.Equal(cur.Load(), int32(2))
	close(release)
	all.Wait()
	is.Equal(peak.Load(), int32(2))
	is.Equal(finished.Load(), int32(5))
}

// Stop cancels running walks and waits for them; afterwards Run refuses work.
func TestAdhocWalksStopCancels(t *testing.T) {
	is := is.New(t)
	a := scanner.NewAdhocWalks(1, time.Hour, slog.Default())
	is.True(errors.Is(a.Run("x", func(context.Context) {}), scanner.ErrWalksNotRunning))
	is.NoErr(a.Start(context.Background()))

	started := make(chan struct{})
	var sawCancel atomic.Bool
	is.NoErr(a.Run("running", func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		sawCancel.Store(true)
	}))
	<-started // "running" holds the only slot, so "queued" has to wait
	queuedRan := atomic.Bool{}
	is.NoErr(a.Run("queued", func(context.Context) { queuedRan.Store(true) }))

	is.NoErr(a.Stop())
	is.True(sawCancel.Load())  // the running walk saw its context cancelled
	is.True(!queuedRan.Load()) // the queued walk never started
	is.True(errors.Is(a.Run("x", func(context.Context) {}), scanner.ErrWalksNotRunning))
}

// Each walk carries the coordinator's deadline.
func TestAdhocWalksDeadline(t *testing.T) {
	is := is.New(t)
	a := scanner.NewAdhocWalks(1, 10*time.Millisecond, slog.Default())
	is.NoErr(a.Start(context.Background()))
	defer a.Stop()
	errc := make(chan error, 1)
	is.NoErr(a.Run("x", func(ctx context.Context) {
		<-ctx.Done()
		errc <- ctx.Err()
	}))
	is.True(errors.Is(<-errc, context.DeadlineExceeded))
}
