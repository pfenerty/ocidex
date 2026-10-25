package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// sweepRepo records the stuck-job sweep's calls. The embedded interface is
// nil, so any other method panics: the test touches only what it names.
type sweepRepo struct {
	repository.JobRepository
	requeued    bool
	staleBefore pgtype.Timestamptz
	cancelRows  int64
}

func (r *sweepRepo) RequeueStuckRunning(_ context.Context, _ repository.RequeueStuckRunningParams) error {
	r.requeued = true
	return nil
}

func (r *sweepRepo) FailStaleRequeuedScanJobs(_ context.Context, before pgtype.Timestamptz) error {
	r.staleBefore = before
	return nil
}

func (r *sweepRepo) CancelQueuedScanJob(_ context.Context, _ pgtype.UUID) (int64, error) {
	return r.cancelRows, nil
}

// ocidex-nps9.26: jobs requeued for retry sat "queued" for days when no worker
// came back for them. The stuck sweep now fails those too, a day after their
// last attempt.
func TestRequeueStuckRunning_AlsoFailsStaleRequeued(t *testing.T) {
	is := is.New(t)
	repo := &sweepRepo{}
	svc := &jobService{repo: repo}

	is.NoErr(svc.RequeueStuckRunning(context.Background(), 10*time.Minute, 3))
	is.True(repo.requeued)
	is.True(repo.staleBefore.Valid)
	age := time.Since(repo.staleBefore.Time)
	is.True(age > staleRequeuedAfter-time.Minute && age < staleRequeuedAfter+time.Minute)
}

func TestCancel_NotQueuedIsNotFound(t *testing.T) {
	is := is.New(t)
	svc := &jobService{repo: &sweepRepo{cancelRows: 0}}
	err := svc.Cancel(context.Background(), "00000000-0000-0000-0000-000000000001")
	is.True(errors.Is(err, ErrNotFound))

	svc = &jobService{repo: &sweepRepo{cancelRows: 1}}
	is.NoErr(svc.Cancel(context.Background(), "00000000-0000-0000-0000-000000000001"))
}
