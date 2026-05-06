package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/pfenerty/ocidex/internal/event"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
)

// enrichmentMaxConcurrency mirrors the MaxAckPending consumer config — limits how many
// enrichment goroutines run concurrently, keeping unacknowledged message count bounded.
const enrichmentMaxConcurrency = 50

// DispatchRunner is implemented by Dispatcher and allows substitution in tests.
type DispatchRunner interface {
	ProcessOne(ctx context.Context, ref SubjectRef) error
}

// NATSExtension replaces the in-process enrichment extension when NATS is enabled.
// It consumes from a durable JetStream pull consumer, providing durability and
// multi-instance coordination. The in-process Extension is not used alongside this.
type NATSExtension struct {
	client      *natspkg.Client
	dispatcher  DispatchRunner
	streamName  string
	logger      *slog.Logger
	msgTimeout  time.Duration // per-message processing deadline; should be < AckWait
	fetchCancel context.CancelFunc
	fetchDone   chan struct{}
	sem         chan struct{} // bounds concurrent goroutines to MaxAckPending
	wg          sync.WaitGroup
}

// NewNATSExtension creates a NATSExtension backed by the given client and dispatcher.
// msgTimeout is the per-message processing deadline; set it slightly under the consumer
// AckWait so a hung goroutine is cancelled before JetStream redelivers to another worker.
func NewNATSExtension(client *natspkg.Client, dispatcher DispatchRunner, streamName string, logger *slog.Logger, msgTimeout time.Duration) *NATSExtension {
	return &NATSExtension{
		client:     client,
		dispatcher: dispatcher,
		streamName: streamName,
		logger:     logger,
		msgTimeout: msgTimeout,
	}
}

// Name returns the extension identifier.
func (e *NATSExtension) Name() string { return "enrichment-nats" }

// Init is a no-op; NATSExtension consumes from JetStream, not the in-process bus.
func (e *NATSExtension) Init(_ *event.Bus) error { return nil }

// Start provisions the durable consumer and starts the fetch loop.
func (e *NATSExtension) Start(ctx context.Context) error {
	provCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Enrichment fetches OCI metadata — faster than scanning but can still be slow
	// for large registries. Higher MaxDeliver because transient failures are common.
	consumer, err := e.client.JS.CreateOrUpdateConsumer(provCtx, e.streamName, jetstream.ConsumerConfig{
		Durable:       "enrichment",
		FilterSubject: e.streamName + ".sbom.ingested",
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       5 * time.Minute,
		MaxDeliver:    5,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxAckPending: enrichmentMaxConcurrency,
	})
	if err != nil {
		return fmt.Errorf("nats enrichment consumer: %w", err)
	}

	e.sem = make(chan struct{}, enrichmentMaxConcurrency)

	fetchCtx, fetchCancel := context.WithCancel(ctx)
	e.fetchCancel = fetchCancel
	e.fetchDone = make(chan struct{})

	go func() {
		defer close(e.fetchDone)
		e.fetchLoop(fetchCtx, consumer)
	}()

	return nil
}

// Stop cancels the fetch loop then waits for all in-flight processing goroutines.
func (e *NATSExtension) Stop() error {
	if e.fetchCancel != nil && e.fetchDone != nil {
		e.fetchCancel()
		<-e.fetchDone
	}
	e.wg.Wait()
	return nil
}

func (e *NATSExtension) fetchLoop(ctx context.Context, consumer jetstream.Consumer) {
	for {
		msgs, err := consumer.Fetch(enrichmentMaxConcurrency, jetstream.FetchMaxWait(2*time.Second))
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
			e.handleMsg(ctx, msg)
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

func (e *NATSExtension) handleMsg(fetchCtx context.Context, msg natsMsg) {
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
		Architecture   string `json:"architecture"`
		BuildDate      string `json:"build_date"`
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
		Architecture:   wire.Architecture,
		BuildDate:      wire.BuildDate,
	}

	// Acquire semaphore slot — blocks when enrichmentMaxConcurrency goroutines are running.
	// This bounds unacknowledged message count to MaxAckPending. If the fetch loop is
	// cancelled while waiting, Nak so JetStream redelivers.
	select {
	case e.sem <- struct{}{}:
	case <-fetchCtx.Done():
		_ = msg.Nak()
		return
	}

	e.wg.Add(1)
	go func() { //nolint:gosec // G118: intentional — enrichment must complete even after fetchCtx cancel
		defer e.wg.Done()
		defer func() { <-e.sem }()

		ctx, cancel := context.WithTimeout(context.Background(), e.msgTimeout) //nolint:gosec // G118: see above
		defer cancel()

		if err := e.dispatcher.ProcessOne(ctx, ref); err != nil {
			e.logger.Error("nats enrichment: processing failed, nacking",
				"artifact_name", ref.ArtifactName, "err", err)
			_ = msg.Nak()
			return
		}
		_ = msg.Ack()
	}()
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
