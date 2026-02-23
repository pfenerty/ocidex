package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nats-io/nats.go/jetstream"

	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/event"
)

// DispatchRunner is implemented by Dispatcher and allows substitution in tests.
type DispatchRunner interface {
	SubmitWithResult(ref SubjectRef) bool
	Run(ctx context.Context)
}

// NATSExtension replaces the in-process enrichment extension when NATS is enabled.
// It consumes from a durable JetStream pull consumer, providing durability and
// multi-instance coordination. The in-process Extension is not used alongside this.
type NATSExtension struct {
	client      *natspkg.Client
	dispatcher  DispatchRunner
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

// NewNATSExtensionWithStream creates a NATSExtension with an explicit stream name.
func NewNATSExtensionWithStream(client *natspkg.Client, dispatcher DispatchRunner, streamName string, logger *slog.Logger) *NATSExtension {
	return &NATSExtension{
		client:     client,
		dispatcher: dispatcher,
		streamName: streamName,
		logger:     logger,
	}
}

// Name returns the extension identifier.
func (e *NATSExtension) Name() string { return "enrichment-nats" }

// Init is a no-op; NATSExtension consumes from JetStream, not the in-process bus.
func (e *NATSExtension) Init(_ *event.Bus) error { return nil }

// Start provisions the durable consumer and starts the fetch loop and dispatcher workers.
func (e *NATSExtension) Start(ctx context.Context) error {
	provCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	consumer, err := e.client.JS.CreateOrUpdateConsumer(provCtx, e.streamName, jetstream.ConsumerConfig{
		Durable:       "enrichment",
		FilterSubject: e.streamName + ".sbom.ingested",
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       5 * time.Minute,
		MaxDeliver:    5,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxAckPending: 50,
	})
	if err != nil {
		return fmt.Errorf("nats enrichment consumer: %w", err)
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
			e.logger.Error("nats enrichment: fetch error", "err", err)
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
		e.logger.Error("nats enrichment: unmarshal envelope", "err", err)
		_ = msg.Term()
		return
	}

	var wire struct {
		SBOMID         string `json:"sbom_id"`
		ArtifactType   string `json:"artifact_type"`
		ArtifactName   string `json:"artifact_name"`
		Digest         string `json:"digest"`
		SubjectVersion string `json:"subject_version"`
	}
	if err := json.Unmarshal(env.Payload, &wire); err != nil {
		e.logger.Error("nats enrichment: unmarshal payload", "err", err)
		_ = msg.Term()
		return
	}

	id, err := parseUUID(wire.SBOMID)
	if err != nil {
		e.logger.Error("nats enrichment: parse uuid", "sbom_id", wire.SBOMID, "err", err)
		_ = msg.Term()
		return
	}

	ref := SubjectRef{
		SBOMId:         id,
		ArtifactType:   wire.ArtifactType,
		ArtifactName:   wire.ArtifactName,
		Digest:         wire.Digest,
		SubjectVersion: wire.SubjectVersion,
	}

	if !e.dispatcher.SubmitWithResult(ref) {
		// Queue full — nack so JetStream redelivers after AckWait.
		_ = msg.Nak()
		return
	}

	// Ack on successful submit. UpsertEnrichment is idempotent so
	// double-processing on redelivery is safe.
	_ = msg.Ack()
}

// parseUUID converts a hyphenated UUID string to pgtype.UUID.
func parseUUID(s string) (pgtype.UUID, error) {
	if len(s) != 36 {
		return pgtype.UUID{}, fmt.Errorf("invalid uuid length: %d", len(s))
	}
	hex := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	var b [16]byte
	for i := range 16 {
		_, err := fmt.Sscanf(hex[i*2:i*2+2], "%02x", &b[i])
		if err != nil {
			return pgtype.UUID{}, fmt.Errorf("parse uuid byte %d: %w", i, err)
		}
	}
	return pgtype.UUID{Bytes: b, Valid: true}, nil
}
