package scanner

import (
	"context"

	"github.com/pfenerty/ocidex/internal/event"
)

// Extension adapts Dispatcher to the extension.Extension interface.
type Extension struct {
	dispatcher *Dispatcher
	cancel     context.CancelFunc
	done       chan struct{}
}

// NewExtension creates a scanner extension backed by the given dispatcher.
func NewExtension(dispatcher *Dispatcher) *Extension {
	return &Extension{dispatcher: dispatcher}
}

// Name returns the extension identifier.
func (e *Extension) Name() string { return "scanner" }

// Init is a no-op — the scanner is driven by inbound HTTP, not internal events.
func (e *Extension) Init(_ *event.Bus) error { return nil }

// Start launches the dispatcher's worker pool in a background goroutine.
func (e *Extension) Start(ctx context.Context) error {
	ctx, e.cancel = context.WithCancel(ctx)
	e.done = make(chan struct{})
	go func() {
		defer close(e.done)
		e.dispatcher.Run(ctx)
	}()
	return nil
}

// Stop cancels the dispatcher context and waits for workers to drain.
func (e *Extension) Stop() error {
	if e.cancel != nil {
		e.cancel()
	}
	if e.done != nil {
		<-e.done
	}
	return nil
}
