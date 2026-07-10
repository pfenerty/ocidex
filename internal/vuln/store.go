package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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

// ListDistinctPurlTypes returns the distinct purl type tokens (e.g. "npm", "pypi").
func (s *PGStore) ListDistinctPurlTypes(ctx context.Context) ([]string, error) {
	return s.q.ListDistinctPurlTypes(ctx)
}

// ListDistinctComponentPurlsByTypes returns purls whose purl type matches any entry in types.
func (s *PGStore) ListDistinctComponentPurlsByTypes(ctx context.Context, types []string) ([]string, error) {
	return s.q.ListDistinctComponentPurlsByTypes(ctx, types)
}

// ListUnknownComponentPurls returns all distinct component purls with no package_vulnerability entry.
func (s *PGStore) ListUnknownComponentPurls(ctx context.Context) ([]string, error) {
	return s.q.ListUnknownComponentPurls(ctx)
}

// ListUnknownPurlsForSBOM returns purls from the given SBOM not yet in package_vulnerability.
func (s *PGStore) ListUnknownPurlsForSBOM(ctx context.Context, sbomID pgtype.UUID) ([]string, error) {
	return s.q.ListUnknownSBOMComponentPurls(ctx, sbomID)
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
		CanonicalID: v.CanonicalID,
		Summary:     text(v.Summary),
		Details:     text(v.Details),
		Severity:    text(v.Severity),
		CvssScore:   float4(v.CVSSScore),
		CvssVector:  text(v.CVSSVector),
		PublishedAt: timestamptz(v.Published),
		ModifiedAt:  timestamptz(v.Modified),
		Raw:         v.Raw,
	})
}

// DeleteVulnerabilityByID deletes a withdrawn vulnerability; FK cascades clean
// up package_vulnerability and vulnerability_reference rows.
func (s *PGStore) DeleteVulnerabilityByID(ctx context.Context, id string) error {
	return s.q.DeleteVulnerabilityByID(ctx, id)
}

// ReplaceVulnerabilityRefs atomically replaces all references for a vulnerability
// (delete then insert in one transaction).
func (s *PGStore) ReplaceVulnerabilityRefs(ctx context.Context, vulnID string, refs []Reference) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	qtx := s.q.WithTx(tx)
	if err := qtx.DeleteVulnerabilityRefs(ctx, vulnID); err != nil {
		return fmt.Errorf("delete refs: %w", err)
	}
	for _, ref := range refs {
		if ref.URL == "" {
			continue
		}
		if err := qtx.InsertVulnerabilityRef(ctx, repository.InsertVulnerabilityRefParams{
			VulnerabilityID: vulnID,
			Type:            ref.Type,
			Url:             ref.URL,
		}); err != nil {
			return fmt.Errorf("insert ref: %w", err)
		}
	}
	return tx.Commit(ctx)
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
	if err := qtx.UpsertPurlVulnState(ctx, purl); err != nil {
		return fmt.Errorf("upsert purl state: %w", err)
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

// GetEcosystemState returns the stored CSV max-modified timestamp for an ecosystem.
// ok=false if no state has been recorded yet (first run).
func (s *PGStore) GetEcosystemState(ctx context.Context, ecosystem string) (time.Time, bool, error) {
	row, err := s.q.GetEcosystemState(ctx, ecosystem)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, err
	}
	if !row.LastModifiedAt.Valid {
		return time.Time{}, false, nil
	}
	return row.LastModifiedAt.Time, true, nil
}

// UpsertEcosystemState persists the latest CSV modified timestamp for an ecosystem.
func (s *PGStore) UpsertEcosystemState(ctx context.Context, ecosystem string, lastModifiedAt time.Time) error {
	return s.q.UpsertEcosystemState(ctx, repository.UpsertEcosystemStateParams{
		Ecosystem:      ecosystem,
		LastModifiedAt: timestamptz(lastModifiedAt),
	})
}

// GetVulnerabilityModifiedAts bulk-fetches stored modified_at timestamps for the
// given vulnerability IDs. Returns only IDs that exist in the DB.
func (s *PGStore) GetVulnerabilityModifiedAts(ctx context.Context, ids []string) (map[string]time.Time, error) {
	rows, err := s.q.GetVulnerabilityModifiedAts(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("bulk modified_at lookup: %w", err)
	}
	out := make(map[string]time.Time, len(rows))
	for _, r := range rows {
		if r.ModifiedAt.Valid {
			out[r.ID] = r.ModifiedAt.Time
		}
	}
	return out, nil
}

// GetVulnerabilitiesRaw bulk-fetches stored raw OSV JSON for the given IDs.
// Returns only IDs that exist in the DB.
func (s *PGStore) GetVulnerabilitiesRaw(ctx context.Context, ids []string) (map[string]json.RawMessage, error) {
	rows, err := s.q.GetVulnerabilitiesRaw(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("bulk raw fetch: %w", err)
	}
	out := make(map[string]json.RawMessage, len(rows))
	for _, r := range rows {
		if len(r.Raw) > 0 {
			out[r.ID] = json.RawMessage(r.Raw)
		}
	}
	return out, nil
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
