// Package extension provides the lifecycle interface for OCIDex extensions.
// Extensions register event subscriptions during Init, start background work
// during Start, and clean up during Stop.
//
// This package is shared infrastructure: the API, scanner-worker, and
// enrichment-worker binaries all construct a Registry to manage their
// extensions identically. It stays at internal/extension rather than being
// split per-binary (audited in ocidex-ujj.62).
package extension

import (
	"context"

	"github.com/pfenerty/ocidex/internal/event"
)

// Extension is implemented by each pluggable subsystem (enrichment, audit, connectors, etc.).
type Extension interface {
	// Name returns a human-readable identifier for logging.
	Name() string

	// Init registers event subscriptions on the bus. Called before any
	// events are published, so there are no race conditions.
	Init(bus *event.Bus) error

	// Start begins background goroutines. The context is cancelled on shutdown.
	Start(ctx context.Context) error

	// Stop performs graceful cleanup (flush queues, close connections, etc.).
	Stop() error
}
