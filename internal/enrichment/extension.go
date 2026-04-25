package enrichment

import (
	"context"
	"log/slog"

	"github.com/pfenerty/ocidex/internal/event"
)

// Extension wraps an enrichment Dispatcher as an extension.Extension,
// bridging the event bus to the existing enrichment pipeline.
type Extension struct {
	dispatcher *Dispatcher
	cancel     context.CancelFunc
	done       chan struct{}
}

// NewExtension creates an enrichment extension backed by the given dispatcher.
func NewExtension(dispatcher *Dispatcher) *Extension {
	return &Extension{dispatcher: dispatcher}
}

// Name returns the extension identifier.
func (e *Extension) Name() string { return "enrichment" }

// Init subscribes to SBOMIngested events so the dispatcher receives work.
func (e *Extension) Init(bus *event.Bus) error {
	bus.Subscribe(event.SBOMIngested, e.handleSBOMIngested)
	return nil
}

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

func (e *Extension) handleSBOMIngested(_ context.Context, ev event.Event) {
	data, ok := ev.Data.(event.SBOMIngestedData)
	if !ok {
		slog.Error("enrichment extension received unexpected event data type")
		return
	}
	e.dispatcher.Submit(SubjectRef{
		SBOMId:         data.SBOMID,
		ArtifactType:   data.ArtifactType,
		ArtifactName:   data.ArtifactName,
		Digest:         data.Digest,
		SubjectVersion: data.SubjectVersion,
		Architecture:   data.Architecture,
		BuildDate:      data.BuildDate,
	})
}
