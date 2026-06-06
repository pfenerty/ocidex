package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// ScanJobState represents the lifecycle state of a scan job.
type ScanJobState string

const (
	ScanJobQueued    ScanJobState = "queued"
	ScanJobRunning   ScanJobState = "running"
	ScanJobSucceeded ScanJobState = "succeeded"
	ScanJobFailed    ScanJobState = "failed"
)

// ScanJob is the domain model for a pipeline scan job.
type ScanJob struct {
	ID            string
	RegistryID    *string
	Repository    string
	Digest        string
	Tag           *string
	State         ScanJobState
	Attempts      int32
	LastError     *string
	NATSMsgID     *string
	SbomID        *string
	CreatedAt     time.Time
	StartedAt     *time.Time
	LastAttemptAt *time.Time
	FinishedAt    *time.Time
	WorkerID      *string
}

// ScanJobClaim is the "ready-to-scan" projection a worker receives after
// claiming a queued row. It includes the registry credentials joined in so
// the worker does not need a second query.
type ScanJobClaim struct {
	ID           string
	RegistryID   string
	Repository   string
	Digest       string
	Tag          string
	RegistryURL  string
	Insecure     bool
	AuthUsername string
	AuthToken    string
	Attempts     int32
}

func (c ScanJobClaim) JobID() string      { return c.ID }
func (c ScanJobClaim) JobAttempts() int32 { return c.Attempts }

// JobService manages the lifecycle of scan pipeline jobs.
type JobService interface {
	Enqueue(ctx context.Context, registryID, repo, digest, tag, msgID string) (ScanJob, error)
	Start(ctx context.Context, msgID, workerID string) error
	Finish(ctx context.Context, msgID string, sbomID pgtype.UUID) error
	Fail(ctx context.Context, msgID, lastError string) error
	List(ctx context.Context, state string, limit, offset int32) ([]ScanJob, int64, error)
	Get(ctx context.Context, id string) (ScanJob, error)
	CountByState(ctx context.Context) (queued, running, succeeded24h, failed24h int64, err error)
	TimeoutJobs(ctx context.Context, olderThan time.Duration) error

	// Outbox-pattern primitives.
	// ClaimByID transitions a specific queued row to running and returns the
	// claim (with registry credentials joined in). The bool is false when the
	// row is missing, already running, or terminal — never an error.
	ClaimByID(ctx context.Context, id, workerID string) (ScanJobClaim, bool, error)
	// ClaimNext picks the oldest queued row and claims it (FOR UPDATE SKIP
	// LOCKED). False when the queue is empty.
	ClaimNext(ctx context.Context, workerID string) (ScanJobClaim, bool, error)
	// FinishByID transitions running → succeeded with an SBOM id.
	FinishByID(ctx context.Context, id string, sbomID pgtype.UUID) error
	// FailOrRequeue either resets state to 'queued' for retry (when
	// attempts < maxAttempts) or marks 'failed' (when attempts >= maxAttempts).
	// Returns the resulting state string. Satisfies jobqueue.Queue[ScanJobClaim].
	FailOrRequeue(ctx context.Context, id, lastError string, maxAttempts int32) (string, error)
	// RequeueStuckRunning sweeps running rows whose worker hasn't updated
	// last_attempt_at within stuckThreshold. They go back to queued, or to
	// failed if they've used up retries. This is the only stuck-job sweep
	// the outbox model needs — no NATS-aware reconciler.
	RequeueStuckRunning(ctx context.Context, stuckThreshold time.Duration, maxAttempts int32) error
	// Retry resets a 'failed' row back to 'queued' so an operator can manually
	// retry a permanently-failed scan.
	Retry(ctx context.Context, id string) error
	// RetryAllFailed resets every 'failed' row back to 'queued'. Returns the
	// number of rows affected.
	RetryAllFailed(ctx context.Context) (int64, error)
}

type jobService struct{ repo repository.JobRepository }

// NewJobService constructs a JobService backed by the given pool.
func NewJobService(pool *pgxpool.Pool) JobService {
	return &jobService{repo: repository.New(pool)}
}

func (s *jobService) Enqueue(ctx context.Context, registryID, repo, digest, tag, msgID string) (ScanJob, error) {
	var regID pgtype.UUID
	if registryID != "" {
		_ = regID.Scan(registryID)
	}
	row, err := s.repo.InsertScanJob(ctx, repository.InsertScanJobParams{
		RegistryID: regID,
		Repository: repo,
		Digest:     digest,
		Tag:        toNullText(nullStr(tag)),
		NatsMsgID:  toNullText(nullStr(msgID)),
	})
	if err != nil {
		return ScanJob{}, fmt.Errorf("inserting scan job: %w", err)
	}
	return fromJobRow(row), nil
}

func (s *jobService) Start(ctx context.Context, msgID, workerID string) error {
	return s.repo.StartScanJob(ctx, repository.StartScanJobParams{
		NatsMsgID: pgtype.Text{String: msgID, Valid: msgID != ""},
		WorkerID:  pgtype.Text{String: workerID, Valid: workerID != ""},
	})
}

func (s *jobService) Finish(ctx context.Context, msgID string, sbomID pgtype.UUID) error {
	return s.repo.FinishScanJob(ctx, repository.FinishScanJobParams{
		NatsMsgID: pgtype.Text{String: msgID, Valid: msgID != ""},
		SbomID:    sbomID,
	})
}

func (s *jobService) Fail(ctx context.Context, msgID, lastError string) error {
	return s.repo.FailScanJob(ctx, repository.FailScanJobParams{
		NatsMsgID: pgtype.Text{String: msgID, Valid: msgID != ""},
		LastError: pgtype.Text{String: lastError, Valid: lastError != ""},
	})
}

func (s *jobService) List(ctx context.Context, state string, limit, offset int32) ([]ScanJob, int64, error) {
	stateFilter := pgtype.Text{String: state, Valid: state != ""}
	rows, err := s.repo.ListScanJobs(ctx, repository.ListScanJobsParams{
		State:  stateFilter,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing scan jobs: %w", err)
	}
	total, err := s.repo.CountScanJobs(ctx, stateFilter)
	if err != nil {
		return nil, 0, fmt.Errorf("counting scan jobs: %w", err)
	}
	out := make([]ScanJob, len(rows))
	for i, r := range rows {
		out[i] = fromJobRow(r)
	}
	return out, total, nil
}

func (s *jobService) Get(ctx context.Context, id string) (ScanJob, error) {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return ScanJob{}, ErrNotFound
	}
	row, err := s.repo.GetScanJob(ctx, uid)
	if err != nil {
		return ScanJob{}, ErrNotFound
	}
	return fromJobRow(row), nil
}

func fromJobRow(r repository.ScanJob) ScanJob {
	j := ScanJob{
		ID:         uuidToStr(r.ID),
		Repository: r.Repository,
		Digest:     r.Digest,
		State:      ScanJobState(r.State),
		Attempts:   r.Attempts,
		CreatedAt:  r.CreatedAt.Time,
	}
	if r.RegistryID.Valid {
		s := uuidToStr(r.RegistryID)
		j.RegistryID = &s
	}
	if r.Tag.Valid {
		j.Tag = &r.Tag.String
	}
	if r.LastError.Valid {
		j.LastError = &r.LastError.String
	}
	if r.NatsMsgID.Valid {
		j.NATSMsgID = &r.NatsMsgID.String
	}
	if r.SbomID.Valid {
		s := uuidToStr(r.SbomID)
		j.SbomID = &s
	}
	if r.StartedAt.Valid {
		t := r.StartedAt.Time
		j.StartedAt = &t
	}
	if r.LastAttemptAt.Valid {
		t := r.LastAttemptAt.Time
		j.LastAttemptAt = &t
	}
	if r.FinishedAt.Valid {
		t := r.FinishedAt.Time
		j.FinishedAt = &t
	}
	if r.WorkerID.Valid {
		j.WorkerID = &r.WorkerID.String
	}
	return j
}

func (s *jobService) TimeoutJobs(ctx context.Context, olderThan time.Duration) error {
	cutoff := pgtype.Timestamptz{}
	_ = cutoff.Scan(time.Now().Add(-olderThan))
	return s.repo.TimeoutScanJobs(ctx, cutoff)
}

func (s *jobService) CountByState(ctx context.Context) (int64, int64, int64, int64, error) {
	since := pgtype.Timestamptz{}
	_ = since.Scan(time.Now().Add(-24 * time.Hour))

	queued, err := s.repo.CountScanJobs(ctx, pgtype.Text{String: "queued", Valid: true})
	if err != nil {
		return 0, 0, 0, 0, err
	}
	running, err := s.repo.CountScanJobs(ctx, pgtype.Text{String: "running", Valid: true})
	if err != nil {
		return 0, 0, 0, 0, err
	}
	succ, err := s.repo.CountScanJobsSince(ctx, repository.CountScanJobsSinceParams{State: "succeeded", Since: since})
	if err != nil {
		return 0, 0, 0, 0, err
	}
	fail, err := s.repo.CountScanJobsSince(ctx, repository.CountScanJobsSinceParams{State: "failed", Since: since})
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return queued, running, succ, fail, nil
}

func (s *jobService) ClaimByID(ctx context.Context, id, workerID string) (ScanJobClaim, bool, error) {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return ScanJobClaim{}, false, nil
	}
	row, err := s.repo.ClaimScanJobByID(ctx, repository.ClaimScanJobByIDParams{
		ID:       uid,
		WorkerID: workerID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ScanJobClaim{}, false, nil
		}
		return ScanJobClaim{}, false, fmt.Errorf("claim scan job by id: %w", err)
	}
	return claimFromRow(row.ID, row.RegistryID, row.Repository, row.Digest,
		row.Tag, row.RegistryUrl, row.Insecure, row.AuthUsername, row.AuthToken, row.Attempts), true, nil
}

func (s *jobService) ClaimNext(ctx context.Context, workerID string) (ScanJobClaim, bool, error) {
	row, err := s.repo.ClaimNextQueuedJob(ctx, workerID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ScanJobClaim{}, false, nil
		}
		return ScanJobClaim{}, false, fmt.Errorf("claim next queued job: %w", err)
	}
	return claimFromRow(row.ID, row.RegistryID, row.Repository, row.Digest,
		row.Tag, row.RegistryUrl, row.Insecure, row.AuthUsername, row.AuthToken, row.Attempts), true, nil
}

func (s *jobService) FinishByID(ctx context.Context, id string, sbomID pgtype.UUID) error {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return fmt.Errorf("invalid job id: %w", err)
	}
	return s.repo.FinishScanJobByID(ctx, repository.FinishScanJobByIDParams{
		ID:     uid,
		SbomID: sbomID,
	})
}

func (s *jobService) FailOrRequeue(ctx context.Context, id, lastError string, maxAttempts int32) (string, error) {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return "", fmt.Errorf("invalid job id: %w", err)
	}
	state, err := s.repo.FailOrRequeueScanJobByID(ctx, repository.FailOrRequeueScanJobByIDParams{
		ID:          uid,
		MaxAttempts: maxAttempts,
		LastError:   pgtype.Text{String: lastError, Valid: lastError != ""},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("fail or requeue scan job: %w", err)
	}
	return state, nil
}

func (s *jobService) RequeueStuckRunning(ctx context.Context, stuckThreshold time.Duration, maxAttempts int32) error {
	cutoff := pgtype.Timestamptz{}
	_ = cutoff.Scan(time.Now().Add(-stuckThreshold))
	return s.repo.RequeueStuckRunning(ctx, repository.RequeueStuckRunningParams{
		MaxAttempts: maxAttempts,
		StuckBefore: cutoff,
	})
}

func (s *jobService) Retry(ctx context.Context, id string) error {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return fmt.Errorf("invalid job id: %w", err)
	}
	return s.repo.RetryScanJob(ctx, uid)
}

func (s *jobService) RetryAllFailed(ctx context.Context) (int64, error) {
	return s.repo.RetryAllFailedScanJobs(ctx)
}

func claimFromRow(id pgtype.UUID, registryID, repo, digest, tag, registryURL string, insecure bool, authUser, authToken string, attempts int32) ScanJobClaim {
	return ScanJobClaim{
		ID:           uuidToStr(id),
		RegistryID:   registryID,
		Repository:   repo,
		Digest:       digest,
		Tag:          tag,
		RegistryURL:  registryURL,
		Insecure:     insecure,
		AuthUsername: authUser,
		AuthToken:    authToken,
		Attempts:     attempts,
	}
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
