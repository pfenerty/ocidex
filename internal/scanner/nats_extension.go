package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/pfenerty/ocidex/internal/event"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
)

// NATSExtension replaces the in-process scanner extension when NATS mode is active.
// It consumes from a durable JetStream pull consumer, providing durability and
// multi-instance coordination. The in-process Extension is not used alongside this.
type NATSExtension struct {
	client      *natspkg.Client
	dispatcher  *Dispatcher
	streamName  string
	logger      *slog.Logger
	fetchCancel context.CancelFunc
	fetchDone   chan struct{}
	dispCancel  context.CancelFunc
	dispDone    chan struct{}
}

// NewNATSExtension creates a NATSExtension backed by the given client and dispatcher.
func NewNATSExtension(client *natspkg.Client, dispatcher *Dispatcher, logger *slog.Logger) *NATSExtension {
	return &NATSExtension{
		client:     client,
		dispatcher: dispatcher,
		streamName: "ocidex",
		logger:     logger,
	}
}

// Name returns the extension identifier.
func (e *NATSExtension) Name() string { return "scanner-nats" }

// Init is a no-op; NATSExtension consumes from JetStream, not the in-process bus.
func (e *NATSExtension) Init(_ *event.Bus) error { return nil }

// Start provisions the durable consumer and starts the fetch loop and dispatcher workers.
func (e *NATSExtension) Start(ctx context.Context) error {
	provCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	consumer, err := e.client.JS.CreateOrUpdateConsumer(provCtx, e.streamName, jetstream.ConsumerConfig{
		Durable:       "scanner",
		FilterSubject: e.streamName + ".scan.requested",
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       10 * time.Minute,
		MaxDeliver:    3,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxAckPending: 10,
	})
	if err != nil {
		return fmt.Errorf("nats scanner consumer: %w", err)
	}

	fetchCtx, fetchCancel := context.WithCancel(ctx)
	dispCtx, dispCancel := context.WithCancel(context.Background())

	e.fetchCancel = fetchCancel
	e.fetchDone = make(chan struct{})
	e.dispCancel = dispCancel
	e.dispDone = make(chan struct{})

	go func() {
		defer close(e.dispDone)
		e.dispatcher.Run(dispCtx)
	}()

	go func() {
		defer close(e.fetchDone)
		e.fetchLoop(fetchCtx, consumer)
	}()

	return nil
}

// Stop performs two-phase shutdown: stop fetching first, then drain the dispatcher.
func (e *NATSExtension) Stop() error {
	if e.fetchCancel != nil {
		e.fetchCancel()
		<-e.fetchDone
	}
	if e.dispCancel != nil {
		e.dispCancel()
		<-e.dispDone
	}
	return nil
}

func (e *NATSExtension) fetchLoop(ctx context.Context, consumer jetstream.Consumer) {
	for {
		msgs, err := consumer.Fetch(10, jetstream.FetchMaxWait(2*time.Second))
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.logger.Error("nats scanner: fetch error", "err", err)
			continue
		}

		for msg := range msgs.Messages() {
			if ctx.Err() != nil {
				_ = msg.Nak()
				continue
			}
			e.handleMsg(msg)
		}

		if ctx.Err() != nil {
			return
		}
	}
}

// natsMsg is the subset of jetstream.Msg used by handleMsg.
type natsMsg interface {
	Data() []byte
	Ack() error
	Nak() error
	Term() error
}

func (e *NATSExtension) handleMsg(msg natsMsg) {
	var env natspkg.Envelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		e.logger.Error("nats scanner: unmarshal envelope", "err", err)
		_ = msg.Term()
		return
	}

	var wire scanRequestWire
	if err := json.Unmarshal(env.Payload, &wire); err != nil {
		e.logger.Error("nats scanner: unmarshal payload", "err", err)
		_ = msg.Term()
		return
	}

	req := ScanRequest{
		RegistryURL:  wire.RegistryURL,
		Insecure:     wire.Insecure,
		Repository:   wire.Repository,
		Digest:       wire.Digest,
		Tag:          wire.Tag,
		Architecture: wire.Architecture,
		BuildDate:    wire.BuildDate,
		ImageVersion: wire.ImageVersion,
	}

	if !e.dispatcher.SubmitWithResult(req) {
		// Queue full — nack so JetStream redelivers after AckWait.
		_ = msg.Nak()
		return
	}

	// Ack on successful submit.
	_ = msg.Ack()
}
