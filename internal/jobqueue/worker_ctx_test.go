package jobqueue

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/matryer/is"
)

// blockingQueue's claims block until their ctx is done, like a query on a
// stuck connection. It records the ctx FailOrRequeue was given.
type blockingQueue struct {
	recordingQueue
	claimDeadline chan bool

	mu sync.Mutex
	// outcomeErr and outcomeDeadline are the outcome ctx's state at the
	// moment FailOrRequeue ran; run cancels that ctx when it returns.
	outcomeErr      error
	outcomeDeadline time.Time
	outcomeBounded  bool
}

func (q *blockingQueue) block(ctx context.Context) (testClaim, bool, error) {
	_, has := ctx.Deadline()
	select {
	case q.claimDeadline <- has:
	default:
	}
	<-ctx.Done()
	return testClaim{}, false, ctx.Err()
}

func (q *blockingQueue) ClaimByID(ctx context.Context, _, _ string) (testClaim, bool, error) {
	return q.block(ctx)
}

func (q *blockingQueue) ClaimNext(ctx context.Context, _ string) (testClaim, bool, error) {
	return q.block(ctx)
}

func (q *blockingQueue) FailOrRequeue(ctx context.Context, id, lastError string, maxAttempts int32) (string, error) {
	q.mu.Lock()
	q.outcomeErr = ctx.Err()
	q.outcomeDeadline, q.outcomeBounded = ctx.Deadline()
	q.mu.Unlock()
	return q.recordingQueue.FailOrRequeue(ctx, id, lastError, maxAttempts)
}

// A worker blocked in a claim stops as soon as its ctx is cancelled: the claim
// runs on the worker's ctx, not context.Background() (ocidex-89c9.3).
func TestWorkerLoopStopsDuringBlockedClaim(t *testing.T) {
	for _, path := range []string{"poll", "hint"} {
		t.Run(path, func(t *testing.T) {
			is := is.New(t)
			q := &blockingQueue{claimDeadline: make(chan bool, 1)}
			w := newTestWorker(q, func(context.Context, testClaim) error { return nil })
			w.cfg.PollInterval = time.Millisecond
			if path == "hint" {
				w.cfg.PollInterval = time.Hour
				w.hints <- "job-1"
			}

			ctx, cancel := context.WithCancel(context.Background())
			w.wg.Add(1)
			go w.workerLoop(ctx)

			select {
			case hasDeadline := <-q.claimDeadline:
				is.True(hasDeadline) // the claim is bounded by claimTimeout
			case <-time.After(5 * time.Second):
				t.Fatal("worker never claimed")
			}

			cancel()
			stopped := make(chan struct{})
			go func() { w.wg.Wait(); close(stopped) }()
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("worker did not stop while its claim was blocked")
			}
		})
	}
}

// A job that fails because its ctx was cancelled still has its outcome
// recorded, on a ctx that is not cancelled but is bounded.
func TestRunRecordsOutcomeAfterCancellation(t *testing.T) {
	is := is.New(t)
	q := &blockingQueue{}
	ctx, cancel := context.WithCancel(context.Background())
	w := newTestWorker(q, func(jobCtx context.Context, _ testClaim) error {
		cancel() // Stop arrives mid-job
		<-jobCtx.Done()
		return jobCtx.Err()
	})

	w.run(ctx, testClaim{id: "job-1", attempts: 1})

	is.Equal(len(q.calls), 1) // the outcome was recorded
	q.mu.Lock()
	defer q.mu.Unlock()
	is.Equal(q.calls[0].lastError, context.Canceled.Error())
	is.NoErr(q.outcomeErr)    // not cancelled with the job...
	is.True(q.outcomeBounded) // ...but bounded
	is.True(time.Until(q.outcomeDeadline) <= outcomeTimeout)
}
