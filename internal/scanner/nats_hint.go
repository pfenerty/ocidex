package scanner

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
	"github.com/pfenerty/ocidex/internal/service"
)

const (
	// scannerHintDurable names the JetStream consumer for scan hints.
	scannerHintDurable = "scanner-hint"
	// hintAckWait is short: NATS does not redeliver — the DB owns retry —
	// so AckWait only matters as a "did the handler ack" timeout.
	hintAckWait = 30 * time.Second
	// hintMaxDeliver is 1: workers ack on receipt; if they crash before the
	// row is processed, the stuck-running sweep picks it up.
	hintMaxDeliver = 1
)

// ScanProcessor scans an image and ingests the resulting SBOM, returning the
// new SBOM's UUID. Implemented by engine.Dispatcher; the indirection keeps
// the scanner package free of Syft.
type ScanProcessor interface {
	ProcessOne(ctx context.Context, req ScanRequest) (pgtype.UUID, error)
}

// NATSHintExtension is the outbox-pattern scanner worker. It consumes "hint"
// messages from JetStream (carrying only a scan_jobs row id) and also polls
// the DB for queued rows as a fallback. Either way it ClaimsByID/Next, runs
// the scan, and Finish/Fails the row.
//
// The DB row is the only source of truth for queued work. NATS hints are a
// latency optimization; if NATS is unavailable or hints are lost, the poll
// loop keeps draining the queue.
type NATSHintExtension struct {
	client     *natspkg.Client
	processor  ScanProcessor
	jobSvc     service.JobService
	streamName string
	workerID   string
	logger     *slog.Logger

	maxConc      int
	pollInterval time.Duration
	scanTimeout  time.Duration
	maxAttempts  int32

	hints chan string // bounded buffer of pending hint ids

	consume      jetstream.ConsumeContext
	workerCancel context.CancelFunc
	wg           sync.WaitGroup
}

// NewNATSHintExtension constructs a hint-driven scanner extension.
// maxConcurrency caps both the worker pool size and the hint buffer.
// pollInterval is the DB poll cadence used as a fallback when no hint arrives.
// scanTimeout bounds a single image scan; maxAttempts is the retry budget
// before a job is permanently failed.
func NewNATSHintExtension(
	client *natspkg.Client,
	processor ScanProcessor,
	jobSvc service.JobService,
	streamName, workerID string,
	logger *slog.Logger,
	maxConcurrency int,
	pollInterval, scanTimeout time.Duration,
	maxAttempts int,
) *NATSHintExtension {
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}
	return &NATSHintExtension{
		client:       client,
		processor:    processor,
		jobSvc:       jobSvc,
		streamName:   streamName,
		workerID:     workerID,
		logger:       logger,
		maxConc:      maxConcurrency,
		pollInterval: pollInterval,
		scanTimeout:  scanTimeout,
		maxAttempts:  int32(maxAttempts), //nolint:gosec // G115: small bounded retry count
		hints:        make(chan string, maxConcurrency*4),
	}
}

// Name returns the extension identifier.
func (e *NATSHintExtension) Name() string { return "scanner-hint" }

// Init is a no-op — this extension does not consume from the in-process bus.
func (e *NATSHintExtension) Init(_ *event.Bus) error { return nil }

// Start provisions the consumer, registers the message handler, and launches
// the worker pool.
func (e *NATSHintExtension) Start(ctx context.Context) error {
	provCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	consumer, err := e.client.JS.CreateOrUpdateConsumer(provCtx, e.streamName, jetstream.ConsumerConfig{
		Durable:       scannerHintDurable,
		FilterSubject: e.streamName + scanHintSubjectSuffix,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       hintAckWait,
		MaxDeliver:    hintMaxDeliver,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxAckPending: cap(e.hints) * 2,
	})
	if err != nil {
		return fmt.Errorf("nats scanner-hint consumer: %w", err)
	}

	cc, err := consumer.Consume(e.handleHint)
	if err != nil {
		return fmt.Errorf("nats scanner-hint consume: %w", err)
	}
	e.consume = cc

	workerCtx, workerCancel := context.WithCancel(ctx)
	e.workerCancel = workerCancel
	for i := 0; i < e.maxConc; i++ {
		e.wg.Add(1)
		go e.workerLoop(workerCtx)
	}
	return nil
}

// Stop tears down the NATS subscription and waits for in-flight scans.
func (e *NATSHintExtension) Stop() error {
	if e.consume != nil {
		e.consume.Stop()
	}
	if e.workerCancel != nil {
		e.workerCancel()
	}
	e.wg.Wait()
	return nil
}

// handleHint is invoked by JetStream for each hint message. We ack immediately
// and push the id into the hints channel. If the channel is full we drop the
// hint; the DB poll loop will catch the row.
func (e *NATSHintExtension) handleHint(msg jetstream.Msg) {
	_ = msg.Ack()

	var hint scanHint
	if err := json.Unmarshal(msg.Data(), &hint); err != nil {
		e.logger.Warn("scan hint: decode failed", "err", err)
		return
	}
	if hint.ID == "" {
		return
	}
	select {
	case e.hints <- hint.ID:
	default:
		// Buffer full; row is in the DB, poll loop will claim it.
	}
}

func (e *NATSHintExtension) workerLoop(ctx context.Context) {
	defer e.wg.Done()
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case id := <-e.hints:
			e.processByID(ctx, id)
			e.drainPoll(ctx)
		case <-ticker.C:
			e.drainPoll(ctx)
		}
	}
}

func (e *NATSHintExtension) processByID(ctx context.Context, id string) {
	claim, ok, err := e.jobSvc.ClaimByID(context.Background(), id, e.workerID)
	if err != nil {
		e.logger.Error("scan claim by id failed", "id", id, "err", err)
		return
	}
	if !ok {
		return
	}
	e.runScan(ctx, claim)
}

func (e *NATSHintExtension) drainPoll(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		claim, ok, err := e.jobSvc.ClaimNext(context.Background(), e.workerID)
		if err != nil {
			e.logger.Error("scan claim next failed", "err", err)
			return
		}
		if !ok {
			return
		}
		e.runScan(ctx, claim)
	}
}

// runScan runs the actual scan and applies the outcome to the DB row. The
// claim has already transitioned queued → running.
func (e *NATSHintExtension) runScan(ctx context.Context, claim service.ScanJobClaim) {
	req := scanRequestFromClaim(claim)
	scanCtx, cancel := context.WithTimeout(ctx, e.scanTimeout)
	defer cancel()

	sbomID, err := e.processor.ProcessOne(scanCtx, req)
	if err != nil {
		e.logger.Error("scan failed",
			"id", claim.ID, "repo", claim.Repository, "digest", claim.Digest,
			"attempts", claim.Attempts, "err", err,
		)
		state, ferr := e.jobSvc.FailOrRequeueByID(context.Background(), claim.ID, err.Error(), e.maxAttempts)
		if ferr != nil {
			e.logger.Error("scan fail-or-requeue failed", "id", claim.ID, "err", ferr)
			return
		}
		e.logger.Info("scan job retry decision",
			"id", claim.ID, "state", state, "attempts", claim.Attempts,
		)
		return
	}
	if ferr := e.jobSvc.FinishByID(context.Background(), claim.ID, sbomID); ferr != nil {
		e.logger.Error("scan finish failed", "id", claim.ID, "err", ferr)
	}
}

func scanRequestFromClaim(c service.ScanJobClaim) ScanRequest {
	return ScanRequest{
		RegistryURL:  c.RegistryURL,
		Insecure:     c.Insecure,
		Repository:   c.Repository,
		Digest:       c.Digest,
		Tag:          c.Tag,
		AuthUsername: c.AuthUsername,
		AuthToken:    c.AuthToken,
		RegistryID:   c.RegistryID,
	}
}
