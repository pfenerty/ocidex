package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/matryer/is"
)

// warmRecorder is a SearchService that only implements the method the warmer
// uses; the rest of the interface is supplied by the embedded nil, which panics
// if the warmer ever reaches for it.
type warmRecorder struct {
	SearchService

	mu         sync.Mutex
	scopes     []string
	discovered int
	err        error
	calls      chan struct{}

	// delay/before/after let a test observe how long a warm takes and how many
	// run at once.
	delay  time.Duration
	before func()
	after  func()
}

func (w *warmRecorder) WarmDashboardStats(_ context.Context, vis VisibilityFilter) (*DashboardStats, error) {
	if w.before != nil {
		w.before()
	}
	if w.after != nil {
		defer w.after()
	}
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	w.mu.Lock()
	w.scopes = append(w.scopes, statsCacheKey(vis))
	w.mu.Unlock()
	if w.calls != nil {
		w.calls <- struct{}{}
	}
	if w.err != nil {
		return nil, w.err
	}
	return &DashboardStats{}, nil
}

// WarmDiscovery participates in before/after so the overlap test covers it too:
// it runs in the same pass and against the same tables, so a pass that let it
// overlap a scope warm would reintroduce exactly the pool exhaustion
// TestStatsWarmerNeverOverlapsPasses guards against.
func (w *warmRecorder) WarmDiscovery(_ context.Context) (*Discovery, error) {
	if w.before != nil {
		w.before()
	}
	if w.after != nil {
		defer w.after()
	}
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	w.mu.Lock()
	w.discovered++
	w.mu.Unlock()
	if w.err != nil {
		return nil, w.err
	}
	return &Discovery{}, nil
}

func (w *warmRecorder) seen() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.scopes...)
}

func (w *warmRecorder) discoveries() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.discovered
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The warmer is the only thing keeping cache entries fresh, so an entry must
// never be able to expire between two warms — otherwise a dashboard load lands
// on the slow path the warmer exists to avoid.
func TestStatsWarmIntervalIsBelowCacheTTL(t *testing.T) {
	is := is.New(t)
	is.True(StatsWarmInterval < statsCacheTTL)
}

func TestStatsWarmerWarmsBothSessionlessScopesOnStart(t *testing.T) {
	is := is.New(t)

	rec := &warmRecorder{calls: make(chan struct{}, 4)}
	// An interval far longer than the test: anything observed here came from
	// the immediate warm on start, not from a tick.
	w := NewStatsWarmer(rec, time.Hour, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// Run warms immediately rather than waiting out the first tick, so the
	// first request after startup already finds a warm cache.
	for i := range 2 {
		select {
		case <-rec.calls:
		case <-time.After(2 * time.Second):
			t.Fatalf("warmer did not warm both scopes on start, saw %v after %d", rec.seen(), i)
		}
	}

	is.Equal(rec.seen(), []string{"anon", "admin"})

	cancel()
	<-done
}

// The public discovery payload has no visibility scope, so it is not one of
// warmedScopes() and would be silently left cold if the warmer only walked that
// list — and a cold discovery cache means the landing page reports warming
// forever, since GetDiscovery never computes on the request path.
func TestStatsWarmerWarmsDiscoveryEachPass(t *testing.T) {
	is := is.New(t)

	rec := &warmRecorder{calls: make(chan struct{}, 64)}
	w := NewStatsWarmer(rec, time.Millisecond, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	// Drain the scope handoffs so the passes can keep making progress.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range rec.calls {
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for rec.discoveries() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("warmer did not stop on context cancellation")
	}
	close(rec.calls)
	<-drained

	// Two, not one: the first proves it warms at all, the second that it keeps
	// warming on the schedule rather than only at startup.
	is.True(rec.discoveries() >= 2)
}

func TestStatsWarmerKeepsTickingAfterAFailure(t *testing.T) {
	is := is.New(t)

	// A failing warm must not kill the loop: a transient DB error would
	// otherwise leave the cache permanently cold, which is the bug itself.
	rec := &warmRecorder{err: errors.New("boom"), calls: make(chan struct{}, 16)}
	w := NewStatsWarmer(rec, 5*time.Millisecond, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	for i := 0; i < 4; i++ {
		select {
		case <-rec.calls:
		case <-time.After(2 * time.Second):
			t.Fatalf("warmer stopped after %d calls", i)
		}
	}

	cancel()
	// Drain so a warm blocked on the unbuffered handoff can return and let
	// Run observe the cancellation.
	go func() {
		for range rec.calls {
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("warmer did not stop on context cancellation")
	}

	is.True(len(rec.seen()) >= 4)
}

// Regression: the warmer used a fixed ticker, so once a pass outlasted the
// interval — which it did in production, ~5.6 minutes against a 5 minute
// period — the next pass started while the previous was still running. Passes
// piled up without bound and held the connection pool permanently, so ordinary
// requests queued for a connection until they hit the HTTP timeout. The
// interval must be a gap between passes, not a period.
func TestStatsWarmerNeverOverlapsPasses(t *testing.T) {
	is := is.New(t)

	var (
		mu      sync.Mutex
		inFlt   int
		maxInFl int
	)
	rec := &warmRecorder{calls: make(chan struct{}, 64)}
	rec.before = func() {
		mu.Lock()
		inFlt++
		if inFlt > maxInFl {
			maxInFl = inFlt
		}
		mu.Unlock()
	}
	rec.after = func() {
		mu.Lock()
		inFlt--
		mu.Unlock()
	}

	// Each warm outlasts the interval several times over: a ticker-driven loop
	// would have a second pass running before the first finished.
	w := NewStatsWarmer(rec, time.Millisecond, discardLogger())
	rec.delay = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	for i := 0; i < 4; i++ {
		select {
		case <-rec.calls:
		case <-time.After(5 * time.Second):
			t.Fatalf("warmer stopped after %d calls", i)
		}
	}

	cancel()
	go func() {
		for range rec.calls {
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("warmer did not stop on context cancellation")
	}

	mu.Lock()
	defer mu.Unlock()
	is.Equal(maxInFl, 1)
}

func TestNewStatsWarmerDefaultsNonPositiveInterval(t *testing.T) {
	is := is.New(t)
	is.Equal(NewStatsWarmer(&warmRecorder{}, 0, discardLogger()).interval, StatsWarmInterval)
	is.Equal(NewStatsWarmer(&warmRecorder{}, -time.Second, discardLogger()).interval, StatsWarmInterval)
}
