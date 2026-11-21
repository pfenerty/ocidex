// Package jobqueue implements the outbox-pattern job worker loop shared by
// scanner-worker and the per-enricher workers.
//
// A Worker[C] drains a DB job queue via three mechanisms:
//  1. NATS hints — fast-path wake-up when a new row is enqueued
//  2. DB poll loop — fallback when hints are lost or NATS is unavailable
//  3. Stuck-running sweep — recovers rows whose worker crashed mid-job
//
// Each job type supplies a Queue[C] (DB operations) and a
// processor func(ctx, C) error that does the work. Finish is called
// inside the processor so each type can store type-specific results.
// Returning a non-nil error from the processor triggers FailOrRequeue, which
// requeues the row until MaxAttempts is exhausted. A processor that wraps its
// error with Permanent() skips the remaining budget and fails the row on the
// spot — see permanent.go.
package jobqueue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/pfenerty/ocidex/internal/event"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
)

// Claim must be implemented by all job claim types.
type Claim interface {
	JobID() string
	JobAttempts() int32
}

// Queue is the per-job-type DB interface required by Worker.
// Finish is intentionally absent: the processor func calls it directly
// so each job type can store type-specific results (e.g. scan → sbom_id).
type Queue[C Claim] interface {
	ClaimByID(ctx context.Context, id, workerID string) (C, bool, error)
	ClaimNext(ctx context.Context, workerID string) (C, bool, error)
	FailOrRequeue(ctx context.Context, id, lastError string, maxAttempts int32) (string, error)
	RequeueStuckRunning(ctx context.Context, threshold time.Duration, maxAttempts int32) error
}

// Database calls the worker makes around a job, each bounded so a stuck
// connection can't hang a worker or Stop (ocidex-89c9.3). A claim is a single
// UPDATE ... RETURNING and the outcome a single UPDATE; the sweep touches only
// rows past the stuck threshold.
const (
	claimTimeout   = 10 * time.Second
	outcomeTimeout = 10 * time.Second
	sweepTimeout   = 30 * time.Second
)

// Config holds tunable parameters for a Worker.
type Config struct {
	WorkerID string
	MaxConc  int
	// PollInterval is the DB poll cadence used as a fallback when no hint arrives.
	PollInterval time.Duration
	// JobTimeout bounds a single job execution.
	JobTimeout time.Duration
	// MaxAttempts is the per-row retry budget before permanent failure.
	MaxAttempts int32
	// StuckThreshold is how long a 'running' row can go without progress
	// before the stuck sweep requeues it.
	StuckThreshold time.Duration
	// HintSubjectSuffix is appended to the stream name, e.g. ".scan.hint".
	HintSubjectSuffix string
	// HintDurable is the JetStream durable consumer name, e.g. "scanner-hint".
	HintDurable string
}

// Worker[C] drives the outbox-pattern job loop and implements extension.Extension.
type Worker[C Claim] struct {
	name       string
	client     *natspkg.Client
	streamName string
	queue      Queue[C]
	processor  func(context.Context, C) error
	cfg        Config
	logger     *slog.Logger
	metrics    workerMetrics
	tracer     trace.Tracer
	spanName   string

	hints        chan string
	consume      jetstream.ConsumeContext
	workerCancel context.CancelFunc
	sweepCancel  context.CancelFunc
	wg           sync.WaitGroup
}

// NewWorker constructs a Worker. name appears in logs and as the extension Name().
// processor receives a claimed job and is responsible for calling Finish on success;
// returning non-nil triggers FailOrRequeue.
func NewWorker[C Claim](
	name string,
	client *natspkg.Client,
	streamName string,
	queue Queue[C],
	processor func(context.Context, C) error,
	cfg Config,
	logger *slog.Logger,
) *Worker[C] {
	if cfg.MaxConc < 1 {
		cfg.MaxConc = 1
	}
	return &Worker[C]{
		name:       name,
		client:     client,
		streamName: streamName,
		queue:      queue,
		processor:  processor,
		cfg:        cfg,
		logger:     logger,
		metrics:    noopWorkerMetrics(),
		tracer:     tracenoop.NewTracerProvider().Tracer(""),
		spanName:   name,
		hints:      make(chan string, cfg.MaxConc*4),
	}
}

func (w *Worker[C]) Name() string            { return w.name }
func (w *Worker[C]) Init(_ *event.Bus) error { return nil }

// Start provisions the NATS hint consumer, runs a startup stuck sweep,
// launches the worker pool, and starts the periodic stuck sweep.
func (w *Worker[C]) Start(ctx context.Context) error {
	w.sweepOnce(ctx, "startup stuck sweep failed")

	provCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// hintAckWait only needs to cover the time between receive and Ack()
	// (which we do immediately). The DB row is the real source of truth.
	const hintAckWait = 30 * time.Second
	// hintMaxDeliver 1: if the worker crashes before claiming, the stuck sweep
	// requeues the row — no need for JetStream to redeliver.
	const hintMaxDeliver = 1

	consumer, err := w.client.JS.CreateOrUpdateConsumer(provCtx, w.streamName, jetstream.ConsumerConfig{
		Durable:       w.cfg.HintDurable,
		FilterSubject: w.streamName + w.cfg.HintSubjectSuffix,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       hintAckWait,
		MaxDeliver:    hintMaxDeliver,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxAckPending: cap(w.hints) * 2,
	})
	if err != nil {
		return fmt.Errorf("%s: provision consumer: %w", w.name, err)
	}

	cc, err := consumer.Consume(w.handleHint)
	if err != nil {
		return fmt.Errorf("%s: consume: %w", w.name, err)
	}
	w.consume = cc

	workerCtx, workerCancel := context.WithCancel(ctx) //nolint:gosec // G118: cancel stored on the worker and invoked in Stop().
	w.workerCancel = workerCancel
	for range w.cfg.MaxConc {
		w.wg.Add(1)
		go w.workerLoop(workerCtx)
	}

	sweepCtx, sweepCancel := context.WithCancel(context.Background()) //nolint:gosec // G118: cancel stored on the worker and invoked in Stop().
	w.sweepCancel = sweepCancel
	w.wg.Add(1)
	go w.runStuckSweep(sweepCtx)

	return nil
}

// Stop cancels the NATS subscription and waits for in-flight jobs. Claims and
// sweeps run on contexts Stop cancels, so a blocked query doesn't hold it up;
// a job's outcome write is bounded by outcomeTimeout.
func (w *Worker[C]) Stop() error {
	if w.consume != nil {
		w.consume.Stop()
	}
	if w.workerCancel != nil {
		w.workerCancel()
	}
	if w.sweepCancel != nil {
		w.sweepCancel()
	}
	w.wg.Wait()
	w.metrics.stop()
	return nil
}

// handleHint is called by JetStream for each hint. We ack immediately and
// push the job id into the hints channel. If the buffer is full we drop the
// hint — the DB poll loop will claim the row.
func (w *Worker[C]) handleHint(msg jetstream.Msg) {
	_ = msg.Ack()
	var hint struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(msg.Data(), &hint); err != nil || hint.ID == "" {
		w.logger.Warn(w.name+": decode hint", "err", err)
		return
	}
	select {
	case w.hints <- hint.ID:
	default:
		// Buffer full; DB poll will claim this row.
	}
}

func (w *Worker[C]) workerLoop(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-w.hints:
			w.processByID(ctx, id)
			w.drainPoll(ctx)
		case <-ticker.C:
			w.drainPoll(ctx)
		}
	}
}

func (w *Worker[C]) processByID(ctx context.Context, id string) {
	claimCtx, cancel := context.WithTimeout(ctx, claimTimeout)
	claim, ok, err := w.queue.ClaimByID(claimCtx, id, w.cfg.WorkerID)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return // stopping
		}
		w.logger.Error(w.name+": claim by id", "id", id, "err", err)
		return
	}
	if !ok {
		return
	}
	w.run(ctx, claim)
}

func (w *Worker[C]) drainPoll(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		claim, ok, err := w.claimNext(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return // stopping
			}
			w.logger.Error(w.name+": claim next", "err", err)
			return
		}
		if !ok {
			return
		}
		w.run(ctx, claim)
	}
}

// claimNext claims the next queued row on the worker's ctx, so Stop interrupts
// it, bounded by claimTimeout. A claim the database committed after the ctx
// gave up leaves its row running; the stuck sweep requeues it.
func (w *Worker[C]) claimNext(ctx context.Context) (C, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, claimTimeout)
	defer cancel()
	return w.queue.ClaimNext(ctx, w.cfg.WorkerID)
}

// failNow is the max-attempts budget passed to FailOrRequeue for a permanent
// error. Both fail queries decide with `attempts >= max_attempts`, and the
// claim query already incremented attempts before the processor ran, so
// attempts >= 1 > 0 and the row goes straight to 'failed' with finished_at set.
// Do not change without re-checking FailOrRequeue{ScanJob,EnrichmentJob}ByID
// in db/queries/.
const failNow int32 = 0

func (w *Worker[C]) run(ctx context.Context, claim C) {
	ctx, span := w.startJobSpan(ctx, claim)
	defer span.End()
	jobCtx, cancel := context.WithTimeout(ctx, w.cfg.JobTimeout)
	defer cancel()

	start := time.Now()
	err := w.processor(jobCtx, claim)
	elapsed := time.Since(start)
	if err == nil {
		w.metrics.record(ctx, outcomeSuccess, elapsed)
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, "job failed")

	permanent := errors.Is(err, ErrPermanent)
	w.logger.Error(w.name+": job failed",
		"id", claim.JobID(), "attempts", claim.JobAttempts(), "permanent", permanent, "err", err,
	)
	maxAttempts := w.cfg.MaxAttempts
	if permanent {
		maxAttempts = failNow
	}
	// The outcome is recorded even when the job failed because ctx was
	// cancelled (a timeout, or Stop), so it runs detached from ctx's
	// cancellation, keeping its values (the span) — but bounded, so a stuck
	// connection can't hold up Stop (ocidex-89c9.3).
	outcomeCtx, cancelOutcome := context.WithTimeout(context.WithoutCancel(ctx), outcomeTimeout)
	defer cancelOutcome()
	state, ferr := w.queue.FailOrRequeue(outcomeCtx, claim.JobID(), err.Error(), maxAttempts)
	// A failed requeue leaves the row running; the stuck sweep retries it.
	outcome := outcomeRetry
	if ferr == nil && state == "failed" {
		outcome = outcomePermanentFailure
	}
	w.metrics.record(ctx, outcome, elapsed)
	span.SetAttributes(attribute.String("ocidex.job.outcome", outcome))
	if ferr != nil {
		w.logger.Error(w.name+": fail-or-requeue", "id", claim.JobID(), "err", ferr)
	} else {
		w.logger.Info(w.name+": retry decision",
			"id", claim.JobID(), "state", state, "attempts", claim.JobAttempts(), "permanent", permanent,
		)
	}
}

func (w *Worker[C]) runStuckSweep(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(w.cfg.StuckThreshold / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.sweepOnce(ctx, "stuck sweep failed")
		case <-ctx.Done():
			return
		}
	}
}

// sweepOnce requeues rows stuck in running, bounded by sweepTimeout.
func (w *Worker[C]) sweepOnce(ctx context.Context, failMsg string) {
	sweepCtx, cancel := context.WithTimeout(ctx, sweepTimeout)
	defer cancel()
	if err := w.queue.RequeueStuckRunning(sweepCtx, w.cfg.StuckThreshold, w.cfg.MaxAttempts); err != nil && ctx.Err() == nil {
		w.logger.Warn(w.name+": "+failMsg, "err", err)
	}
}
