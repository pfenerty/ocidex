package jobqueue

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"
)

// testClaim is a minimal Claim for exercising Worker.run.
type testClaim struct {
	id       string
	attempts int32
}

func (c testClaim) JobID() string      { return c.id }
func (c testClaim) JobAttempts() int32 { return c.attempts }

// recordingQueue captures the arguments Worker.run passes to FailOrRequeue.
// Only FailOrRequeue is exercised; the claim methods are unreachable from run.
type recordingQueue struct {
	calls []failCall
}

type failCall struct {
	id          string
	lastError   string
	maxAttempts int32
}

func (q *recordingQueue) ClaimByID(context.Context, string, string) (testClaim, bool, error) {
	return testClaim{}, false, nil
}

func (q *recordingQueue) ClaimNext(context.Context, string) (testClaim, bool, error) {
	return testClaim{}, false, nil
}

func (q *recordingQueue) FailOrRequeue(_ context.Context, id, lastError string, maxAttempts int32) (string, error) {
	q.calls = append(q.calls, failCall{id: id, lastError: lastError, maxAttempts: maxAttempts})
	if maxAttempts == failNow {
		return "failed", nil
	}
	return "queued", nil
}

func (q *recordingQueue) RequeueStuckRunning(context.Context, time.Duration, int32) error {
	return nil
}

func newTestWorker(q Queue[testClaim], processor func(context.Context, testClaim) error) *Worker[testClaim] {
	return NewWorker("test", nil, "TEST", q, processor, Config{
		MaxAttempts: 3,
		JobTimeout:  time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestRun_RetryBudget verifies that a permanent error collapses the retry budget
// to failNow while an ordinary error keeps the configured MaxAttempts. Passing 0
// is what makes the fail query's `attempts >= max_attempts` branch fire on the
// first attempt (ocidex-9eu4).
func TestRun_RetryBudget(t *testing.T) {
	inner := errors.New("unsupported layer media type")

	cases := []struct {
		name            string
		err             error
		wantMaxAttempts int32
	}{
		{"permanent", Permanent(inner), failNow},
		{"transient", inner, 3},
		{"permanent wrapped again", fmt.Errorf("scan: %w", Permanent(inner)), failNow},
		{"success", nil, -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)

			q := &recordingQueue{}
			w := newTestWorker(q, func(context.Context, testClaim) error { return tc.err })

			w.run(t.Context(), testClaim{id: "job-1", attempts: 1})

			if tc.wantMaxAttempts < 0 {
				is.Equal(len(q.calls), 0)
				return
			}
			is.Equal(len(q.calls), 1)
			is.Equal(q.calls[0].maxAttempts, tc.wantMaxAttempts)
			is.Equal(q.calls[0].id, "job-1")
			// last_error must keep the underlying cause so operators can see why.
			is.True(strings.Contains(q.calls[0].lastError, "unsupported layer media type"))
		})
	}
}

// TestPermanent verifies the wrapper's errors.Is behaviour in both directions:
// the sentinel is matchable by the worker, and the original error is still
// matchable by anything downstream that cares about the specific cause.
func TestPermanent(t *testing.T) {
	is := is.New(t)

	inner := errors.New("boom")
	wrapped := Permanent(inner)

	is.True(errors.Is(wrapped, ErrPermanent))
	is.True(errors.Is(wrapped, inner))
	is.True(strings.HasPrefix(wrapped.Error(), "permanent: "))
	is.True(strings.Contains(wrapped.Error(), "boom"))

	// Safe to apply unconditionally.
	is.Equal(Permanent(nil), nil)

	// A bare error must not match the sentinel.
	is.True(!errors.Is(inner, ErrPermanent))
}
