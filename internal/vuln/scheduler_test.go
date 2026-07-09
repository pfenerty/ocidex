package vuln

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/matryer/is"
)

var errFakeQuery = errors.New("simulated OSV query failure")

func TestScheduler_BackoffOnFailure(t *testing.T) {
	is := is.New(t)
	ctx := context.Background()

	store := newFakeStore("pkg:npm/foo@1.0.0")
	osv := &fakeOSV{err: errFakeQuery}
	svc := NewRefreshService(store, osv, nil)
	sched := NewScheduler(svc, store, time.Minute, nil)

	// First attempt fails: backoff set to the floor, no success recorded.
	sched.runIfDue(ctx)
	is.Equal(osv.queryCalls, 1)
	is.True(!store.refreshed)
	is.Equal(sched.backoff, backoffFloor)

	// Retrying immediately (as the next tick would) must be suppressed —
	// this is the bug: previously every tick re-ran regardless of backoff.
	sched.runIfDue(ctx)
	is.Equal(osv.queryCalls, 1)

	// Once the floor has elapsed, the next attempt fires and, on failure
	// again, the backoff doubles.
	sched.lastAttempt = time.Now().Add(-backoffFloor - time.Second)
	sched.runIfDue(ctx)
	is.Equal(osv.queryCalls, 2)
	is.Equal(sched.backoff, 2*backoffFloor)

	// Backoff is capped rather than growing unbounded.
	sched.backoff = backoffCap
	sched.lastAttempt = time.Now().Add(-backoffCap - time.Second)
	sched.runIfDue(ctx)
	is.Equal(osv.queryCalls, 3)
	is.Equal(sched.backoff, backoffCap)

	// A subsequent success resets the backoff entirely.
	osv.err = nil
	sched.lastAttempt = time.Now().Add(-backoffCap - time.Second)
	sched.runIfDue(ctx)
	is.Equal(osv.queryCalls, 4)
	is.True(store.refreshed)
	is.Equal(sched.backoff, time.Duration(0))

	// A fresh failure after the reset starts back at the floor, not the
	// previously capped value.
	osv.err = errFakeQuery
	sched.runIfDue(ctx)
	is.Equal(osv.queryCalls, 5)
	is.Equal(sched.backoff, backoffFloor)
}
