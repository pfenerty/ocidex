package service

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Agent write budgets (ADR-0058 A6), per key and hour.
const (
	// QuotaScans counts requests that queue scan work.
	QuotaScans = "scans"
	// QuotaWrites counts every request that changes something.
	QuotaWrites = "writes"

	DefaultAgentScansPerHour  = 20
	DefaultAgentWritesPerHour = 120
	MaxAgentScansPerHour      = 200
	MaxAgentWritesPerHour     = 1000

	// MaxAgentIngestImages bounds one ingest-unknown call from an agent key,
	// which must name the images it wants scanned.
	MaxAgentIngestImages = 200
)

// QuotaService counts agent writes against per-key hourly budgets.
type QuotaService interface {
	// Consume counts one action of class for key and reports whether it is
	// within limit. A limit of 0 refuses every action of the class.
	Consume(ctx context.Context, apiKeyID, class string, limit int) (allowed bool, used int, err error)
	// Refund gives back one action of class counted this hour.
	Refund(ctx context.Context, apiKeyID, class string) error
}

type quotaService struct{ q *repository.Queries }

// NewQuotaService returns a QuotaService backed by pool.
func NewQuotaService(pool *pgxpool.Pool) QuotaService {
	return &quotaService{q: repository.New(pool)}
}

func (s *quotaService) Consume(ctx context.Context, apiKeyID, class string, limit int) (bool, int, error) {
	kid, err := parseID(apiKeyID)
	if err != nil {
		return false, 0, err
	}
	used, err := s.q.ConsumeKeyQuota(ctx, repository.ConsumeKeyQuotaParams{ApiKeyID: kid, Class: class})
	if err != nil {
		return false, 0, fmt.Errorf("counting key quota: %w", err)
	}
	if used == 1 {
		// First action this hour: a good moment to drop the key's old windows.
		_ = s.q.PruneKeyQuotaWindows(ctx, kid)
	}
	return int(used) <= limit, int(used), nil
}

func (s *quotaService) Refund(ctx context.Context, apiKeyID, class string) error {
	kid, err := parseID(apiKeyID)
	if err != nil {
		return err
	}
	return s.q.RefundKeyQuota(ctx, repository.RefundKeyQuotaParams{ApiKeyID: kid, Class: class})
}

// agentLimit resolves a key's budget: its override, else the default.
func agentLimit(override *int, def int) int {
	if override != nil {
		return *override
	}
	return def
}
