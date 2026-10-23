package service

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// RetentionMinKeepLast is the smallest non-zero RetentionPolicy.KeepLast: an
// artifact always keeps its newest changelog entry (ADR-0056 R3).
const RetentionMinKeepLast = 2

// RetentionPolicy is the installation-wide retention configuration (ADR-0056 R5).
type RetentionPolicy struct {
	// KeepLast is class N's versions kept per series; 0 turns class N off.
	KeepLast int
	// MaxAge, when positive, also prunes class N versions ingested longer ago.
	MaxAge time.Duration
	// RegistryWindow turns class W on.
	RegistryWindow bool
}

// Validate rejects a policy ADR-0056 does not allow.
func (p RetentionPolicy) Validate() error {
	switch {
	case p.KeepLast < 0:
		return errors.New("retention keep_last must not be negative")
	case p.KeepLast > 0 && p.KeepLast < RetentionMinKeepLast:
		return fmt.Errorf("retention keep_last must be 0 (off) or at least %d", RetentionMinKeepLast)
	case p.MaxAge < 0:
		return errors.New("retention max_age must not be negative")
	}
	return nil
}

// RetentionCandidates are the SBOMs a policy would prune, per class.
type RetentionCandidates struct {
	Window []pgtype.UUID // class W, registry SBOMs out of their window
	Newest []pgtype.UUID // class N, past the newest N versions or max age
}

// PruneCounts is how many SBOMs one Prune call deleted, per class.
type PruneCounts struct {
	Window int64
	Newest int64
}

// Total is the SBOMs deleted across classes.
func (c PruneCounts) Total() int64 { return c.Window + c.Newest }

// RetentionService selects and deletes SBOMs under ADR-0056.
type RetentionService interface {
	// Candidates lists up to limit SBOMs per class that policy would prune,
	// oldest first; limit <= 0 lists them all. It deletes nothing (dry-run).
	Candidates(ctx context.Context, policy RetentionPolicy, limit int) (RetentionCandidates, error)
	// Prune deletes up to batch SBOMs per class, each class in its own
	// transaction, and reports how many went. Repeat until it returns zero.
	Prune(ctx context.Context, policy RetentionPolicy, batch int) (PruneCounts, error)
}

type retentionService struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewRetentionService constructs a RetentionService.
func NewRetentionService(pool *pgxpool.Pool) RetentionService {
	return &retentionService{pool: pool, now: time.Now}
}

func (s *retentionService) Candidates(ctx context.Context, policy RetentionPolicy, limit int) (RetentionCandidates, error) {
	if err := policy.Validate(); err != nil {
		return RetentionCandidates{}, err
	}
	q := repository.New(s.pool)
	var out RetentionCandidates
	var err error
	if out.Window, err = s.windowCandidates(ctx, q, policy, limit); err != nil {
		return RetentionCandidates{}, err
	}
	if out.Newest, err = s.newestCandidates(ctx, q, policy, limit); err != nil {
		return RetentionCandidates{}, err
	}
	return out, nil
}

func (s *retentionService) Prune(ctx context.Context, policy RetentionPolicy, batch int) (PruneCounts, error) {
	if err := policy.Validate(); err != nil {
		return PruneCounts{}, err
	}
	if batch <= 0 {
		return PruneCounts{}, errors.New("retention batch must be positive")
	}
	var counts PruneCounts
	var err error
	if counts.Window, err = s.pruneClass(ctx, func(q *repository.Queries) ([]pgtype.UUID, error) {
		return s.windowCandidates(ctx, q, policy, batch)
	}); err != nil {
		return counts, fmt.Errorf("pruning out-of-window sboms: %w", err)
	}
	if counts.Newest, err = s.pruneClass(ctx, func(q *repository.Queries) ([]pgtype.UUID, error) {
		return s.newestCandidates(ctx, q, policy, batch)
	}); err != nil {
		return counts, fmt.Errorf("pruning old versions: %w", err)
	}
	return counts, nil
}

// pruneClass lists one batch and deletes it in one transaction. The delete
// checks the protected set again (ADR-0056 R6).
func (s *retentionService) pruneClass(ctx context.Context, list func(*repository.Queries) ([]pgtype.UUID, error)) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on committed tx is a no-op

	q := repository.New(tx)
	ids, err := list(q)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	n, err := q.DeleteRetentionBatch(ctx, ids)
	if err != nil {
		return 0, fmt.Errorf("deleting sboms: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing transaction: %w", err)
	}
	return n, nil
}

func (s *retentionService) windowCandidates(ctx context.Context, q *repository.Queries, policy RetentionPolicy, limit int) ([]pgtype.UUID, error) {
	if !policy.RegistryWindow {
		return nil, nil
	}
	ids, err := q.ListRetentionWindowCandidates(ctx, rowLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("listing out-of-window sboms: %w", err)
	}
	return ids, nil
}

func (s *retentionService) newestCandidates(ctx context.Context, q *repository.Queries, policy RetentionPolicy, limit int) ([]pgtype.UUID, error) {
	if policy.KeepLast == 0 {
		return nil, nil
	}
	var cutoff pgtype.Timestamptz
	if policy.MaxAge > 0 {
		cutoff = pgtype.Timestamptz{Time: s.now().Add(-policy.MaxAge), Valid: true}
	}
	ids, err := q.ListRetentionNewestCandidates(ctx, repository.ListRetentionNewestCandidatesParams{
		KeepLast: int64(policy.KeepLast),
		Cutoff:   cutoff,
		RowLimit: rowLimit(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("listing old versions: %w", err)
	}
	return ids, nil
}

// rowLimit maps "no limit" (<= 0) to the largest LIMIT the query accepts.
func rowLimit(limit int) int32 {
	if limit <= 0 || limit > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(limit)
}
