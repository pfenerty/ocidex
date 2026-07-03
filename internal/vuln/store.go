package vuln

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// PGStore is the Postgres-backed Store used by the refresh loop.
type PGStore struct {
	pool *pgxpool.Pool
	q    *repository.Queries
}

// NewPGStore constructs a PGStore over the given pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool, q: repository.New(pool)}
}

// ListDistinctComponentPurls returns every purl present in any SBOM.
func (s *PGStore) ListDistinctComponentPurls(ctx context.Context) ([]string, error) {
	return s.q.ListDistinctComponentPurls(ctx)
}

// UpsertVulnerability inserts or updates one vulnerability record.
func (s *PGStore) UpsertVulnerability(ctx context.Context, v Row) error {
	// aliases is NOT NULL: a nil slice encodes as SQL NULL (the column DEFAULT
	// only applies when the column is omitted), so coalesce to an empty array.
	aliases := v.Aliases
	if aliases == nil {
		aliases = []string{}
	}
	return s.q.UpsertVulnerability(ctx, repository.UpsertVulnerabilityParams{
		ID:          v.ID,
		Aliases:     aliases,
		Summary:     text(v.Summary),
		Details:     text(v.Details),
		Severity:    text(v.Severity),
		CvssScore:   float4(v.CVSSScore),
		PublishedAt: timestamptz(v.Published),
		ModifiedAt:  timestamptz(v.Modified),
		Raw:         v.Raw,
	})
}

// ReplacePackageVulns atomically replaces all mappings for a purl (delete then
// insert in one transaction) so a reader never sees a purl with no vulns
// mid-refresh.
func (s *PGStore) ReplacePackageVulns(ctx context.Context, purl string, refs []PackageVulnRef) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	qtx := s.q.WithTx(tx)
	if err := qtx.DeletePackageVulnsForPurl(ctx, purl); err != nil {
		return fmt.Errorf("delete mappings: %w", err)
	}
	for _, ref := range refs {
		if err := qtx.UpsertPackageVuln(ctx, repository.UpsertPackageVulnParams{
			Purl:            purl,
			VulnerabilityID: ref.VulnerabilityID,
			FixedVersion:    text(ref.FixedVersion),
		}); err != nil {
			return fmt.Errorf("insert mapping: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// LastRefreshedAt returns the last successful refresh time.
func (s *PGStore) LastRefreshedAt(ctx context.Context) (time.Time, bool, error) {
	ts, err := s.q.GetVulnRefreshState(ctx)
	if err != nil {
		return time.Time{}, false, err
	}
	if !ts.Valid {
		return time.Time{}, false, nil
	}
	return ts.Time, true, nil
}

// MarkRefreshed stamps the refresh as complete now.
func (s *PGStore) MarkRefreshed(ctx context.Context) error {
	return s.q.SetVulnRefreshedAt(ctx)
}

func text(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func float4(f *float32) pgtype.Float4 {
	if f == nil {
		return pgtype.Float4{}
	}
	return pgtype.Float4{Float32: *f, Valid: true}
}

func timestamptz(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t, Valid: true}
}
