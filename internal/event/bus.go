package event

import (
	"context"
	"log/slog"
	"sync"
)

// Handler processes an event. Implementations must not panic — but the bus
// recovers panics defensively so one bad handler cannot crash the process.
type Handler func(ctx context.Context, e Event)

// Publisher is the write-side interface of the bus. Services depend on this
// rather than on *Bus directly so they can be tested with a fake.
type Publisher interface {
	Publish(ctx context.Context, t Type, data any)
}

// Bus is a synchronous, in-process publish/subscribe event bus.
// Handlers are called in subscription order on the publisher's goroutine.
type Bus struct {
	mu       sync.RWMutex
	handlers map[Type][]Handler
	logger   *slog.Logger
}

// NewBus creates a new event bus.
func NewBus(logger *slog.Logger) *Bus {
	return &Bus{
		handlers: make(map[Type][]Handler),
		logger:   logger,
	}
}

// Subscribe registers a handler for the given event type.
// Must be called before Publish (typically during extension Init).
func (b *Bus) Subscribe(t Type, h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[t] = append(b.handlers[t], h)
}

// Publish dispatches an event to all registered handlers synchronously.
// Each handler is wrapped in a panic recovery so one misbehaving handler
// cannot take down the process.
func (b *Bus) Publish(ctx context.Context, t Type, data any) {
	b.mu.RLock()
	handlers := b.handlers[t]
	b.mu.RUnlock()

	e := Event{Type: t, Data: data}
	for _, h := range handlers {
		b.safeCall(ctx, e, h)
	}
}

func (b *Bus) safeCall(ctx context.Context, e Event, h Handler) {
	defer func() {
		if r := recover(); r != nil {
			b.logger.Error("event handler panicked",
				"event_type", e.Type,
				"panic", r,
			)
		}
	}()
	h(ctx, e)
}
