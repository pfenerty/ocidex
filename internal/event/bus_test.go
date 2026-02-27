package event

import (
	"context"
	"log/slog"
	"testing"

	matryer "github.com/matryer/is"
)

func TestBus(t *testing.T) {
	tests := []struct {
		name      string
		subscribe []Type
		publish   Type
		wantCalls int
	}{
		{
			name:      "handler receives matching event",
			subscribe: []Type{SBOMIngested},
			publish:   SBOMIngested,
			wantCalls: 1,
		},
		{
			name:      "handler does not receive non-matching event",
			subscribe: []Type{SBOMIngested},
			publish:   SBOMDeleted,
			wantCalls: 0,
		},
		{
			name:      "multiple handlers for same event",
			subscribe: []Type{SBOMIngested, SBOMIngested},
			publish:   SBOMIngested,
			wantCalls: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := matryer.New(t)
			bus := NewBus(slog.Default())

			calls := 0
			for _, typ := range tt.subscribe {
				bus.Subscribe(typ, func(_ context.Context, _ Event) {
					calls++
				})
			}

			bus.Publish(t.Context(), tt.publish, nil)
			is.Equal(calls, tt.wantCalls)
		})
	}
}

func TestBus_PanicRecovery(t *testing.T) {
	is := matryer.New(t)
	bus := NewBus(slog.Default())

	secondCalled := false

	bus.Subscribe(SBOMIngested, func(_ context.Context, _ Event) {
		panic("boom")
	})
	bus.Subscribe(SBOMIngested, func(_ context.Context, _ Event) {
		secondCalled = true
	})

	// Should not panic, and second handler should still run.
	bus.Publish(t.Context(), SBOMIngested, nil)
	is.True(secondCalled)
}

func TestBus_EventDataPassthrough(t *testing.T) {
	is := matryer.New(t)
	bus := NewBus(slog.Default())

	var received Event
	bus.Subscribe(SBOMIngested, func(_ context.Context, e Event) {
		received = e
	})

	data := SBOMIngestedData{ArtifactName: "test-image"}
	bus.Publish(t.Context(), SBOMIngested, data)

	is.Equal(received.Type, SBOMIngested)
	got, ok := received.Data.(SBOMIngestedData)
	is.True(ok)
	is.Equal(got.ArtifactName, "test-image")
}

// Verify *Bus satisfies Publisher.
var _ Publisher = (*Bus)(nil)
