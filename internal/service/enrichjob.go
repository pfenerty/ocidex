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

// EnrichJobClaim is the "ready-to-enrich" projection a worker receives after
// claiming a queued enrichment_jobs row. The sbom and artifact data are joined
// in so the worker does not need a second query.
type EnrichJobClaim struct {
	ID             string
	SBOMId         pgtype.UUID
	Attempts       int32
	EnricherName   string
	Architecture   string
	BuildDate      string
	Digest         string
	IndexDigest    string
	SubjectVersion string
	ArtifactType   string
	ArtifactName   string
}

func (c EnrichJobClaim) JobID() string      { return c.ID }
func (c EnrichJobClaim) JobAttempts() int32 { return c.Attempts }

// EnrichJobService manages the lifecycle of enrichment pipeline jobs.
type EnrichJobService interface {
	// Enqueue writes a new enrichment_jobs row. The idempotency key prevents
	// duplicate rows for the same SBOM+enricher pair; if a row already exists, nil is returned.
	Enqueue(ctx context.Context, sbomID pgtype.UUID, architecture, buildDate, enricherName string) error

	// ClaimByID transitions a specific queued row to running. The bool is false
	// when the row is missing, already running, or terminal.
	ClaimByID(ctx context.Context, id, workerID string) (EnrichJobClaim, bool, error)
	// ClaimNext picks the oldest queued row and claims it (FOR UPDATE SKIP LOCKED).
	// False when the queue is empty.
	ClaimNext(ctx context.Context, workerID string) (EnrichJobClaim, bool, error)
	// FinishByID transitions running → succeeded.
	FinishByID(ctx context.Context, id string) error
	// FailOrRequeue transitions to 'queued' for retry or 'failed' if retries are
	// exhausted. Returns the resulting state string.
	// Satisfies jobqueue.Queue[EnrichJobClaim].
	FailOrRequeue(ctx context.Context, id, lastError string, maxAttempts int32) (string, error)
	// RequeueStuckRunning sweeps running rows whose worker has gone silent.
	RequeueStuckRunning(ctx context.Context, stuckThreshold time.Duration, maxAttempts int32) error

	// List returns enrichment jobs for the admin Jobs page, optionally filtered
	// by state and/or enricher, with the total count for pagination.
	List(ctx context.Context, state, enricherName string, limit, offset int32) ([]EnrichJob, int64, error)
	// Summary returns per-(enricher, state) counts for the health matrix.
	Summary(ctx context.Context) ([]EnrichJobStateCount, error)
	// Retry resets a single 'failed' row back to 'queued'.
	Retry(ctx context.Context, id string) error
	// RetryAllFailed resets every 'failed' row back to 'queued', optionally scoped
	// to one enricher (empty = all enrichers). Returns the number of rows affected.
	RetryAllFailed(ctx context.Context, enricherName string) (int64, error)
}

// EnrichJob is the domain model for an enrichment pipeline job as shown on the
// admin Jobs page. SbomDigest and ArtifactName are joined in for display and may
// be nil when the SBOM has been deleted.
type EnrichJob struct {
	ID            string
	SbomID        *string
	EnricherName  string
	State         string
	Attempts      int32
	LastError     *string
	WorkerID      *string
	SbomDigest    *string
	ArtifactName  *string
	CreatedAt     time.Time
	StartedAt     *time.Time
	LastAttemptAt *time.Time
	FinishedAt    *time.Time
}

// EnrichJobStateCount is one cell of the per-enricher health matrix.
type EnrichJobStateCount struct {
	EnricherName string
	State        string
	Count        int64
}

type enrichJobService struct {
	repo         repository.EnrichmentJobRepository
	enricherName string
}

// NewEnrichJobService constructs an EnrichJobService backed by the given pool.
// enricherName scopes ClaimNext to a specific enricher queue partition; use "all"
// for the legacy single-enricher model.
func NewEnrichJobService(pool *pgxpool.Pool, enricherName string) EnrichJobService {
	return &enrichJobService{repo: repository.New(pool), enricherName: enricherName}
}

func (s *enrichJobService) Enqueue(ctx context.Context, sbomID pgtype.UUID, architecture, buildDate, enricherName string) error {
	// Key per (sbom, enricher): the submitter enqueues one row per enricher for
	// the same SBOM, so a sbom-only key collides on the idempotency_key UNIQUE
	// constraint and silently drops every enricher after the first. This mirrors
	// the UNIQUE (sbom_id, enricher_name) constraint and keeps re-enqueues idempotent.
	idempotencyKey := uuidToStr(sbomID) + ":" + enricherName
	_, err := s.repo.InsertEnrichmentJob(ctx, repository.InsertEnrichmentJobParams{
		SbomID:         sbomID,
		IdempotencyKey: pgtype.Text{String: idempotencyKey, Valid: true},
		Architecture:   pgtype.Text{String: architecture, Valid: architecture != ""},
		BuildDate:      pgtype.Text{String: buildDate, Valid: buildDate != ""},
		EnricherName:   enricherName,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil
		}
		return fmt.Errorf("inserting enrichment job: %w", err)
	}
	return nil
}

func (s *enrichJobService) ClaimByID(ctx context.Context, id, workerID string) (EnrichJobClaim, bool, error) {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return EnrichJobClaim{}, false, nil
	}
	row, err := s.repo.ClaimEnrichmentJobByID(ctx, repository.ClaimEnrichmentJobByIDParams{
		ID:       uid,
		WorkerID: workerID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EnrichJobClaim{}, false, nil
		}
		return EnrichJobClaim{}, false, fmt.Errorf("claim enrichment job by id: %w", err)
	}
	return enrichClaimFromRow(row), true, nil
}

func (s *enrichJobService) ClaimNext(ctx context.Context, workerID string) (EnrichJobClaim, bool, error) {
	row, err := s.repo.ClaimNextEnrichmentJob(ctx, repository.ClaimNextEnrichmentJobParams{
		WorkerID:     workerID,
		EnricherName: s.enricherName,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EnrichJobClaim{}, false, nil
		}
		return EnrichJobClaim{}, false, fmt.Errorf("claim next enrichment job: %w", err)
	}
	return enrichClaimFromNextRow(row), true, nil
}

func (s *enrichJobService) FinishByID(ctx context.Context, id string) error {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return fmt.Errorf("invalid enrichment job id: %w", err)
	}
	return s.repo.FinishEnrichmentJobByID(ctx, uid)
}

func (s *enrichJobService) FailOrRequeue(ctx context.Context, id, lastError string, maxAttempts int32) (string, error) {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return "", fmt.Errorf("invalid enrichment job id: %w", err)
	}
	state, err := s.repo.FailOrRequeueEnrichmentJobByID(ctx, repository.FailOrRequeueEnrichmentJobByIDParams{
		ID:          uid,
		MaxAttempts: maxAttempts,
		LastError:   pgtype.Text{String: lastError, Valid: lastError != ""},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("fail or requeue enrichment job: %w", err)
	}
	return state, nil
}

func (s *enrichJobService) RequeueStuckRunning(ctx context.Context, stuckThreshold time.Duration, maxAttempts int32) error {
	cutoff := pgtype.Timestamptz{}
	_ = cutoff.Scan(time.Now().Add(-stuckThreshold))
	return s.repo.RequeueStuckEnrichmentJobs(ctx, repository.RequeueStuckEnrichmentJobsParams{
		MaxAttempts: maxAttempts,
		StuckBefore: cutoff,
	})
}

func (s *enrichJobService) List(ctx context.Context, state, enricherName string, limit, offset int32) ([]EnrichJob, int64, error) {
	stateFilter := pgtype.Text{String: state, Valid: state != ""}
	enricherFilter := pgtype.Text{String: enricherName, Valid: enricherName != ""}
	rows, err := s.repo.ListEnrichmentJobs(ctx, repository.ListEnrichmentJobsParams{
		State:        stateFilter,
		EnricherName: enricherFilter,
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing enrichment jobs: %w", err)
	}
	total, err := s.repo.CountEnrichmentJobs(ctx, repository.CountEnrichmentJobsParams{
		State:        stateFilter,
		EnricherName: enricherFilter,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("counting enrichment jobs: %w", err)
	}
	out := make([]EnrichJob, len(rows))
	for i, r := range rows {
		out[i] = fromEnrichJobRow(r)
	}
	return out, total, nil
}

func (s *enrichJobService) Summary(ctx context.Context) ([]EnrichJobStateCount, error) {
	rows, err := s.repo.SummarizeEnrichmentJobs(ctx)
	if err != nil {
		return nil, fmt.Errorf("summarizing enrichment jobs: %w", err)
	}
	out := make([]EnrichJobStateCount, len(rows))
	for i, r := range rows {
		out[i] = EnrichJobStateCount{EnricherName: r.EnricherName, State: r.State, Count: r.Count}
	}
	return out, nil
}

func (s *enrichJobService) Retry(ctx context.Context, id string) error {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return fmt.Errorf("invalid job id: %w", err)
	}
	return s.repo.RetryEnrichmentJob(ctx, uid)
}

func (s *enrichJobService) RetryAllFailed(ctx context.Context, enricherName string) (int64, error) {
	return s.repo.RetryAllFailedEnrichmentJobs(ctx, pgtype.Text{String: enricherName, Valid: enricherName != ""})
}

func fromEnrichJobRow(r repository.ListEnrichmentJobsRow) EnrichJob {
	j := EnrichJob{
		ID:           uuidToStr(r.ID),
		EnricherName: r.EnricherName,
		State:        r.State,
		Attempts:     r.Attempts,
		CreatedAt:    r.CreatedAt.Time,
	}
	if r.SbomID.Valid {
		v := uuidToStr(r.SbomID)
		j.SbomID = &v
	}
	if r.LastError.Valid {
		j.LastError = &r.LastError.String
	}
	if r.WorkerID.Valid {
		j.WorkerID = &r.WorkerID.String
	}
	if r.SbomDigest.Valid {
		j.SbomDigest = &r.SbomDigest.String
	}
	if r.ArtifactName.Valid {
		j.ArtifactName = &r.ArtifactName.String
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
	return j
}

func enrichClaimFromRow(r repository.ClaimEnrichmentJobByIDRow) EnrichJobClaim {
	return EnrichJobClaim{
		ID:             uuidToStr(r.ID),
		SBOMId:         r.SbomID,
		Attempts:       r.Attempts,
		Architecture:   r.Architecture,
		BuildDate:      r.BuildDate,
		Digest:         r.Digest,
		IndexDigest:    r.IndexDigest,
		SubjectVersion: r.SubjectVersion,
		ArtifactType:   r.ArtifactType,
		ArtifactName:   r.ArtifactName,
	}
}

func enrichClaimFromNextRow(r repository.ClaimNextEnrichmentJobRow) EnrichJobClaim {
	return EnrichJobClaim{
		ID:             uuidToStr(r.ID),
		SBOMId:         r.SbomID,
		Attempts:       r.Attempts,
		EnricherName:   r.EnricherName,
		Architecture:   r.Architecture,
		BuildDate:      r.BuildDate,
		Digest:         r.Digest,
		IndexDigest:    r.IndexDigest,
		SubjectVersion: r.SubjectVersion,
		ArtifactType:   r.ArtifactType,
		ArtifactName:   r.ArtifactName,
	}
}
