package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/pfenerty/ocidex/internal/event"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/service"
)

// catalogWalkRequestWire is the wire format for catalog walk requests published to NATS.
type catalogWalkRequestWire struct {
	RegistryID string `json:"registry_id"`
}

// NATSCatalogPublisher implements RegistryWalker by publishing a catalog walk
// request to JetStream. The actual walk runs in the scanner-worker process.
type NATSCatalogPublisher struct {
	client     *natspkg.Client
	streamName string
}

// NewNATSCatalogPublisher creates a NATSCatalogPublisher.
func NewNATSCatalogPublisher(client *natspkg.Client, streamName string) *NATSCatalogPublisher {
	return &NATSCatalogPublisher{client: client, streamName: streamName}
}

// Walk publishes a catalog.walk.requested message for the given registry.
// Returns (0, nil) on success; actual queued count is determined by the scanner-worker.
func (p *NATSCatalogPublisher) Walk(ctx context.Context, reg service.Registry) (int, error) {
	payload, err := json.Marshal(catalogWalkRequestWire{RegistryID: reg.ID})
	if err != nil {
		return 0, err
	}
	env := natspkg.Envelope{
		EventType:  "catalog.walk.requested",
		OccurredAt: time.Now().UTC(),
		Payload:    payload,
	}
	data, err := json.Marshal(env)
	if err != nil {
		return 0, err
	}

	pubCtx, cancel := context.WithTimeout(ctx, natsPublishTimeout)
	defer cancel()

	subject := p.streamName + ".catalog.walk.requested"
	msg := nats.NewMsg(subject)
	msg.Header.Set("Nats-Msg-Id", "catalog-walk-"+reg.ID)
	msg.Data = data
	_, err = p.client.JS.PublishMsg(pubCtx, msg)
	return 0, err
}

// NATSCatalogExtension consumes catalog.walk.requested messages from JetStream and
// performs the registry catalog walk inside the scanner-worker process.
type NATSCatalogExtension struct {
	client       *natspkg.Client
	registrySvc  service.RegistryService
	digestLister DigestLister
	submitter    Submitter
	streamName   string
	logger       *slog.Logger
	fetchCancel  context.CancelFunc
	fetchDone    chan struct{}
}

// NewNATSCatalogExtension creates a NATSCatalogExtension.
func NewNATSCatalogExtension(
	client *natspkg.Client,
	registrySvc service.RegistryService,
	digestLister DigestLister,
	submitter Submitter,
	streamName string,
	logger *slog.Logger,
) *NATSCatalogExtension {
	return &NATSCatalogExtension{
		client:       client,
		registrySvc:  registrySvc,
		digestLister: digestLister,
		submitter:    submitter,
		streamName:   streamName,
		logger:       logger,
	}
}

func (e *NATSCatalogExtension) Name() string            { return "catalog-nats" }
func (e *NATSCatalogExtension) Init(_ *event.Bus) error { return nil }

// Start provisions the durable consumer and begins the fetch loop.
func (e *NATSCatalogExtension) Start(ctx context.Context) error {
	provCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// AckWait exceeds the worst-case walk duration (30 min context + buffer).
	consumer, err := e.client.JS.CreateOrUpdateConsumer(provCtx, e.streamName, jetstream.ConsumerConfig{
		Durable:       "catalog-walker",
		FilterSubject: e.streamName + ".catalog.walk.requested",
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       35 * time.Minute,
		MaxDeliver:    2,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxAckPending: 5,
	})
	if err != nil {
		return fmt.Errorf("nats catalog consumer: %w", err)
	}

	fetchCtx, fetchCancel := context.WithCancel(ctx)
	e.fetchCancel = fetchCancel
	e.fetchDone = make(chan struct{})

	go func() {
		defer close(e.fetchDone)
		e.fetchLoop(fetchCtx, consumer)
	}()

	return nil
}

// Stop cancels the fetch loop and waits for it to exit.
func (e *NATSCatalogExtension) Stop() error {
	if e.fetchCancel != nil && e.fetchDone != nil {
		e.fetchCancel()
		<-e.fetchDone
	}
	return nil
}

func (e *NATSCatalogExtension) fetchLoop(ctx context.Context, consumer jetstream.Consumer) {
	for {
		// Fetch one at a time: walks are slow and resource-intensive.
		msgs, err := consumer.Fetch(1, jetstream.FetchMaxWait(2*time.Second))
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.logger.Error("nats catalog: fetch error", "err", err)
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

func (e *NATSCatalogExtension) handleMsg(ctx context.Context, msg natsMsg) {
	var env natspkg.Envelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		e.logger.Error("nats catalog: unmarshal envelope", "err", err)
		_ = msg.Term()
		return
	}

	var wire catalogWalkRequestWire
	if err := json.Unmarshal(env.Payload, &wire); err != nil {
		e.logger.Error("nats catalog: unmarshal payload", "err", err)
		_ = msg.Term()
		return
	}

	walkCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	reg, err := e.registrySvc.Get(walkCtx, wire.RegistryID)
	if err != nil {
		e.logger.Error("nats catalog: fetching registry", "registry_id", wire.RegistryID, "err", err)
		_ = msg.Nak()
		return
	}

	known := FetchKnownDigests(walkCtx, e.digestLister, reg.ID)
	queued, err := WalkRegistry(walkCtx, reg, e.submitter, known, e.logger)
	if err != nil {
		e.logger.Error("nats catalog: walk failed", "registry", reg.Name, "err", err)
		_ = msg.Nak()
		return
	}

	e.logger.Info("nats catalog: walk complete", "registry", reg.Name, "queued", queued)
	_ = msg.Ack()
}
