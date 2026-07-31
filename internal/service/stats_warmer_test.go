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

	mu     sync.Mutex
	scopes []string
	err    error
	calls  chan struct{}
}

func (w *warmRecorder) WarmDashboardStats(_ context.Context, vis VisibilityFilter) (*DashboardStats, error) {
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

func (w *warmRecorder) seen() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.scopes...)
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

func TestNewStatsWarmerDefaultsNonPositiveInterval(t *testing.T) {
	is := is.New(t)
	is.Equal(NewStatsWarmer(&warmRecorder{}, 0, discardLogger()).interval, StatsWarmInterval)
	is.Equal(NewStatsWarmer(&warmRecorder{}, -time.Second, discardLogger()).interval, StatsWarmInterval)
}
