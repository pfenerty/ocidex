package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/pfenerty/ocidex/internal/event"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/service"
)

// scannerMaxConcurrency mirrors the MaxAckPending consumer config — limits how many
// scan goroutines run concurrently, which keeps unacknowledged message count bounded.
const scannerMaxConcurrency = 10

// ScanProcessor processes a single scan request synchronously.
// Implemented by *Dispatcher; allows substitution in tests.
type ScanProcessor interface {
	ProcessOne(ctx context.Context, req ScanRequest) error
}

// NATSExtension replaces the in-process scanner extension when NATS mode is active.
// It consumes from a durable JetStream pull consumer, providing durability and
// multi-instance coordination. The in-process Extension is not used alongside this.
type NATSExtension struct {
	client      *natspkg.Client
	processor   ScanProcessor
	streamName  string
	logger      *slog.Logger
	jobSvc      service.JobService // optional; nil disables job tracking
	fetchCancel context.CancelFunc
	fetchDone   chan struct{}
	sem         chan struct{} // bounds concurrent goroutines to MaxAckPending
	wg          sync.WaitGroup
}

// NewNATSExtension creates a NATSExtension backed by the given client and processor.
func NewNATSExtension(client *natspkg.Client, processor ScanProcessor, streamName string, logger *slog.Logger, jobSvc service.JobService) *NATSExtension {
	return &NATSExtension{
		client:     client,
		processor:  processor,
		streamName: streamName,
		logger:     logger,
		jobSvc:     jobSvc,
	}
}

// Name returns the extension identifier.
func (e *NATSExtension) Name() string { return "scanner-nats" }

// Init is a no-op; NATSExtension consumes from JetStream, not the in-process bus.
func (e *NATSExtension) Init(_ *event.Bus) error { return nil }

// Start provisions the durable consumer and starts the fetch loop.
func (e *NATSExtension) Start(ctx context.Context) error {
	provCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Scanning involves pulling and analyzing OCI images, which is slow.
	// AckWait must exceed the worst-case scan duration.
	consumer, err := e.client.JS.CreateOrUpdateConsumer(provCtx, e.streamName, jetstream.ConsumerConfig{
		Durable:       "scanner",
		FilterSubject: e.streamName + ".scan.requested",
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       10 * time.Minute,
		MaxDeliver:    3,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxAckPending: scannerMaxConcurrency,
	})
	if err != nil {
		return fmt.Errorf("nats scanner consumer: %w", err)
	}

	e.sem = make(chan struct{}, scannerMaxConcurrency)

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
		msgs, err := consumer.Fetch(scannerMaxConcurrency, jetstream.FetchMaxWait(2*time.Second))
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
	Headers() nats.Header
	Ack() error
	Nak() error
	Term() error
}

func (e *NATSExtension) handleMsg(fetchCtx context.Context, msg natsMsg) {
	msgID := ""
	if h := msg.Headers(); h != nil {
		msgID = h.Get("Nats-Msg-Id")
	}

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
		AuthUsername: wire.AuthUsername,
		AuthToken:    wire.AuthToken,
		RegistryID:   wire.RegistryID,
		MsgID:        msgID,
	}

	if e.jobSvc != nil && msgID != "" {
		if err := e.jobSvc.Start(context.Background(), msgID); err != nil {
			e.logger.Warn("scan_jobs: failed to start job", "msg_id", msgID, "err", err)
		}
	}

	// Acquire semaphore slot — blocks when scannerMaxConcurrency goroutines are running.
	// This bounds unacknowledged message count to MaxAckPending. If the fetch loop is
	// cancelled while waiting, Nak so JetStream redelivers.
	select {
	case e.sem <- struct{}{}:
	case <-fetchCtx.Done():
		_ = msg.Nak()
		return
	}

	e.wg.Add(1)
	go func() { //nolint:gosec // G118: intentional — scan must complete even after fetchCtx cancel
		defer e.wg.Done()
		defer func() { <-e.sem }()

		if err := e.processor.ProcessOne(context.Background(), req); err != nil { //nolint:gosec // G118: see above
			e.logger.Error("nats scanner: processing failed, nacking",
				"repo", req.Repository, "digest", req.Digest, "err", err)
			_ = msg.Nak()
			return
		}
		_ = msg.Ack()
	}()
}
