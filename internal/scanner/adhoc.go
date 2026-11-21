package scanner

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/pfenerty/ocidex/internal/event"
)

// ErrWalkInProgress is returned by AdhocWalks.Run when a walk with the same key
// is already queued or running.
var ErrWalkInProgress = errors.New("a walk of this registry is already in progress")

// ErrWalksNotRunning is returned by AdhocWalks.Run before Start or after Stop.
var ErrWalksNotRunning = errors.New("ad-hoc walks are not accepting work")

// AdhocWalks owns the catalog walks started by POST /registries/{id}/scan
// (ocidex-89c9.2). Each walk used to run in a bare goroutine off
// context.Background(), so N requests started N overlapping walks of one
// registry, nothing bounded how many ran at once, and a deploy killed them
// with no record. AdhocWalks gives each walk:
//
//   - per-key dedupe: a second Run for a registry whose walk is queued or
//     running returns ErrWalkInProgress;
//   - a global concurrency bound: at most maxConcurrent walks run, and the rest
//     wait their turn (one per registry at most, so the queue is bounded too);
//   - a deadline, and cancellation on shutdown: walks run under the context
//     Start was given, and Stop cancels it and waits for them.
//
// It is an extension so the extension manager starts it with the process's
// extension context and stops it on shutdown.
type AdhocWalks struct {
	name    string
	sem     chan struct{}
	timeout time.Duration
	logger  *slog.Logger

	mu      sync.Mutex
	running map[string]struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewAdhocWalks returns a coordinator that runs at most maxConcurrent walks at
// a time, each bounded by timeout.
func NewAdhocWalks(maxConcurrent int, timeout time.Duration, logger *slog.Logger) *AdhocWalks {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &AdhocWalks{
		name:    "adhoc-walks",
		sem:     make(chan struct{}, maxConcurrent),
		timeout: timeout,
		logger:  logger,
		running: map[string]struct{}{},
	}
}

// Named sets the extension name, for a process running more than one
// coordinator (registry walks and cluster auto-ingest, say).
func (a *AdhocWalks) Named(name string) *AdhocWalks {
	a.name = name
	return a
}

// Name returns the extension identifier.
func (a *AdhocWalks) Name() string { return a.name }

// Init is a no-op: AdhocWalks subscribes to nothing.
func (a *AdhocWalks) Init(_ *event.Bus) error { return nil }

// Start makes Run accept work. Walks run under a context derived from ctx, so
// cancelling ctx stops them too.
func (a *AdhocWalks) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ctx, a.cancel = context.WithCancel(ctx)
	return nil
}

// Stop cancels every queued and running walk and waits for them to return.
func (a *AdhocWalks) Stop() error {
	a.mu.Lock()
	cancel := a.cancel
	a.ctx, a.cancel = nil, nil
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	a.wg.Wait()
	return nil
}

// Run starts walk in the background under key, returning once it is queued.
// It returns ErrWalkInProgress if a walk with that key is already queued or
// running, and ErrWalksNotRunning outside Start and Stop.
//
// The walk's ctx carries parent's values (the request's trace span and audit
// actor, so the scan jobs it queues stay on the request's trace) but not its
// cancellation: it is cancelled by Stop and by the coordinator's deadline.
func (a *AdhocWalks) Run(parent context.Context, key string, walk func(ctx context.Context)) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctx == nil {
		return ErrWalksNotRunning
	}
	if _, busy := a.running[key]; busy {
		return ErrWalkInProgress
	}
	a.running[key] = struct{}{}
	base := a.ctx
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer a.release(key)
		select {
		case a.sem <- struct{}{}:
			defer func() { <-a.sem }()
		case <-base.Done():
		}
		// select picks at random when both are ready, so a walk can win the
		// semaphore just as shutdown frees it: check again.
		if base.Err() != nil {
			a.logger.Info("ad-hoc walk cancelled before it started", "key", key)
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), a.timeout)
		defer cancel()
		stop := context.AfterFunc(base, cancel)
		defer stop()
		walk(ctx)
	}()
	return nil
}

func (a *AdhocWalks) release(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.running, key)
}
