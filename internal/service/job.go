package service

import (
	"context"
	"fmt"
	"time"

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
	ID         string
	RegistryID *string
	Repository string
	Digest     string
	Tag        *string
	State      ScanJobState
	Attempts   int32
	LastError  *string
	NATSMsgID  *string
	SbomID     *string
	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
}

// JobService manages the lifecycle of scan pipeline jobs.
type JobService interface {
	Enqueue(ctx context.Context, registryID, repo, digest, tag, msgID string) (ScanJob, error)
	Start(ctx context.Context, msgID string) error
	Finish(ctx context.Context, msgID string, sbomID pgtype.UUID) error
	Fail(ctx context.Context, msgID, lastError string) error
	List(ctx context.Context, state string, limit, offset int32) ([]ScanJob, int64, error)
	Get(ctx context.Context, id string) (ScanJob, error)
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

func (s *jobService) Start(ctx context.Context, msgID string) error {
	return s.repo.StartScanJob(ctx, pgtype.Text{String: msgID, Valid: msgID != ""})
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
	if r.FinishedAt.Valid {
		t := r.FinishedAt.Time
		j.FinishedAt = &t
	}
	return j
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
