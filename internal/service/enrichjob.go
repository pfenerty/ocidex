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
	idempotencyKey := uuidToStr(sbomID)
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

func enrichClaimFromRow(r repository.ClaimEnrichmentJobByIDRow) EnrichJobClaim {
	return EnrichJobClaim{
		ID:             uuidToStr(r.ID),
		SBOMId:         r.SbomID,
		Attempts:       r.Attempts,
		Architecture:   r.Architecture,
		BuildDate:      r.BuildDate,
		Digest:         r.Digest,
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
		SubjectVersion: r.SubjectVersion,
		ArtifactType:   r.ArtifactType,
		ArtifactName:   r.ArtifactName,
	}
}
